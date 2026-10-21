// The Kiyesi browser snippet (PRD feature 7). It reports uncaught errors,
// unhandled promise rejections and failed requests from a site's pages,
// and tags the site's own requests with an ID the web server's log also
// records, so an error can be matched to the backend's line for it.
//
// Privacy (PRD): it never reads what people type, cookies, storage or the
// page's content, and it drops the query and fragment of every address.
// Email addresses and token-like values in messages and paths are masked
// before anything leaves the page; the service masks again.
//
// Manners: it never throws into the page, sends each error once per page
// and at most ten reports per page, and sends without waiting for an
// answer (sendBeacon), so it cannot slow the page down.
//
//   <script src="https://cdn.kiyesi.dev/v1/browser.js"
//     data-key="ksk_…" data-version="2.14.0" async></script>
//
// Optional: data-trace-origins="https://api.example.com" adds request IDs
// to those sites' requests too. Only list sites whose server allows the
// X-Request-Id header from your pages, or their requests would be refused.
//
// Traces (PRD feature 18): for the site's own requests that are slow
// (data-slow-ms, 1000 by default) or fail, it reports how long the browser
// waited, with the request's ID, so the request can be followed through
// the web server and the backend. At most 20 a page. A request it did not
// tag uses the ID its answer carries in X-Request-Id, when there is one.

(() => {
  const w = window;
  const doc = document;
  // Loaded twice, it still reports once.
  if ((w as unknown as { __kiyesi?: boolean }).__kiyesi) return;
  (w as unknown as { __kiyesi?: boolean }).__kiyesi = true;

  const script = doc.currentScript as HTMLScriptElement | null;
  const attr = (name: string) => script?.getAttribute(name) ?? "";
  const key = attr("data-key");
  if (!/^ksk_[A-Za-z0-9_-]{20,}$/.test(key)) return;
  const version = attr("data-version").slice(0, 64);
  const endpoint = `${attr("data-endpoint") || "https://api.kiyesi.dev"}/v1/browser/errors?k=${encodeURIComponent(key)}`;
  const traced = new Set([location.origin]);
  for (const o of attr("data-trace-origins").split(/[\s,]+/)) {
    try {
      if (o) traced.add(new URL(o).origin);
    } catch {}
  }

  const slowMs = Number(attr("data-slow-ms")) || 1000;
  const MAX = 10;
  let sent = 0;
  let timings = 0;
  const seen = new Set<string>();

  /** An address without its query or fragment, which can carry values. */
  const clean = (u: string) => {
    try {
      const x = new URL(u, location.href);
      return x.origin + x.pathname;
    } catch {
      return "";
    }
  };
  /**
   * Masks what could name a person or open an account: email addresses,
   * secrets after a name such as password= or Bearer, and long token-like
   * strings of letters and digits (24 or more). Roughly the service's own
   * rules, kept short. A stack keeps its long strings, which are the
   * bundles' file names its frames need.
   */
  const M = "[masked]";
  const maskStack = (s: string) =>
    s
      .replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, M)
      .replace(/\b(bearer|basic)\s+[\w.~+/=-]{8,}/gi, `$1 ${M}`)
      .replace(
        /((?:password|passwd|pwd|secret|token|api[_-]?key|auth|session|cookie)[\w.-]*["']?\s*[:=]\s*["']?)[^\s"',;&]{3,}/gi,
        `$1${M}`,
      );
  const mask = (s: string) =>
    maskStack(s).replace(/[\w-]{24,}/g, (t) => (/\d/.test(t) && /[a-z]/i.test(t) ? M : t));
  /** Stack frames keep their file, line and column, but no query part. */
  const stackOf = (s: unknown) =>
    typeof s === "string" ? s.replace(/\?[^\s):]*/g, "").slice(0, 8000) : "";

  const RID = /^[A-Za-z0-9_-]{8,64}$/;
  /** The ID an answer carries, when the server gives one and lets the page read it. */
  const answerId = (v: string | null | undefined) => (v && RID.test(v) ? v : undefined);

  const id = () => {
    try {
      return crypto.randomUUID();
    } catch {
      return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 14)}`;
    }
  };

  type Report = {
    kind: "error" | "rejection" | "request" | "timing";
    type: string;
    message: string;
    stack: string;
    requestId?: string;
    method?: string;
    path?: string;
    status?: number;
    ms?: number;
  };

  function report(r: Report) {
    try {
      if (r.kind === "timing") {
        if (timings++ >= 20) return;
      } else {
        if (sent >= MAX) return;
        const print = `${r.type}|${r.message}|${r.stack.slice(0, 300)}`;
        if (seen.has(print)) return;
        seen.add(print);
        sent++;
      }
      const body = JSON.stringify({
        ...r,
        message: mask(r.message.slice(0, 1000)),
        stack: maskStack(r.stack),
        ...(r.path ? { path: mask(r.path) } : {}),
        page: mask(clean(location.href)),
        version,
        at: new Date().toISOString(),
      });
      // text/plain, so the browser sends it without asking first (no preflight).
      if (!navigator.sendBeacon?.(endpoint, body)) {
        void origFetch?.(endpoint, {
          method: "POST",
          body,
          keepalive: true,
          mode: "no-cors",
          credentials: "omit",
          headers: { "content-type": "text/plain" },
        }).catch(() => {});
      }
    } catch {}
  }

  w.addEventListener("error", (e) => {
    // Only the page's own errors; a missing image is not one.
    if (!(e instanceof ErrorEvent)) return;
    const err = e.error as Error | undefined;
    report({
      kind: "error",
      type: err?.name || "Error",
      message: String(err?.message ?? e.message ?? ""),
      stack:
        stackOf(err?.stack) || (e.filename ? `at ${clean(e.filename)}:${e.lineno}:${e.colno}` : ""),
    });
  });

  w.addEventListener("unhandledrejection", (e) => {
    const r = e.reason as unknown;
    const err = r instanceof Error ? r : null;
    report({
      kind: "rejection",
      type: err?.name || "UnhandledRejection",
      message: err ? err.message : String(r).slice(0, 1000),
      stack: stackOf(err?.stack),
    });
  });

  /** Where a request goes, and whether it is one of the site's own. */
  const target = (u: string) => {
    try {
      const x = new URL(u, location.href);
      return {
        path: x.pathname,
        own: traced.has(x.origin),
        ours: x.href.startsWith(endpoint.split("?")[0] ?? ""),
      };
    } catch {
      return { path: "", own: false, ours: false };
    }
  };

  /**
   * A request has finished: a 5xx or no answer is an error; one of the
   * site's own that was slow goes to its trace. `status` 0 is no answer.
   */
  const done = (
    method: string,
    path: string,
    rid: string | undefined,
    status: number,
    start: number,
    stack: string,
  ) => {
    const m = method.toUpperCase();
    const ms = Math.round(performance.now() - start);
    const facts = { method: m, path, status, ms, ...(rid ? { requestId: rid } : {}) };
    if (status === 0 || status >= 500)
      report({
        kind: "request",
        type: "Request failed",
        message: `${m} ${path} ${status ? `returned ${status}` : "got no answer"}`,
        stack,
        ...facts,
      });
    else if (rid && ms >= slowMs)
      report({
        kind: "timing",
        type: "Slow request",
        message: `${m} ${path}`,
        stack: "",
        ...facts,
      });
  };

  // fetch: tag the site's own requests, and report 5xx answers and requests
  // that got no answer at all.
  const origFetch = w.fetch?.bind(w);
  if (origFetch) {
    w.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      let t = { path: "", own: false, ours: true };
      let method = "GET";
      let rid: string | undefined;
      let stack = "";
      const start = performance.now();
      try {
        const url = input instanceof Request ? input.url : String(input);
        t = target(url);
        method = init?.method || (input instanceof Request ? input.method : "GET");
        if (!t.ours) {
          stack = stackOf(new Error().stack?.split("\n").slice(2).join("\n"));
          if (t.own) {
            rid = id();
            const headers = new Headers(
              init?.headers ?? (input instanceof Request ? input.headers : undefined),
            );
            if (!headers.has("x-request-id")) headers.set("x-request-id", rid);
            else rid = headers.get("x-request-id") ?? rid;
            init = { ...init, headers };
          }
        }
      } catch {}
      return origFetch(input, init).then(
        (res) => {
          if (!t.ours)
            done(
              method,
              t.path,
              rid ?? answerId(res.headers.get("x-request-id")),
              res.status,
              start,
              stack,
            );
          return res;
        },
        (err: unknown) => {
          // A request the page itself cancelled, or gave a time limit, is not a failure.
          const gaveUp =
            err instanceof DOMException &&
            (err.name === "AbortError" || err.name === "TimeoutError");
          if (!t.ours && !gaveUp) done(method, t.path, rid, 0, start, stack);
          throw err;
        },
      );
    };
  }

  // XMLHttpRequest, for older code and libraries that use it.
  const X = w.XMLHttpRequest?.prototype;
  if (X) {
    const open = X.open;
    const send = X.send;
    type Tagged = XMLHttpRequest & {
      __k?: { method: string; t: ReturnType<typeof target>; rid?: string };
    };
    X.open = function (this: Tagged, method: string, url: string | URL, ...rest: unknown[]) {
      try {
        this.__k = { method, t: target(String(url)) };
      } catch {}
      return (open as (...a: unknown[]) => void).call(this, method, url, ...rest);
    };
    X.send = function (this: Tagged, body?: Document | XMLHttpRequestBodyInit | null) {
      try {
        const k = this.__k;
        if (k && !k.t.ours) {
          if (k.t.own) {
            k.rid = id();
            this.setRequestHeader("X-Request-Id", k.rid);
          }
          const stack = stackOf(new Error().stack?.split("\n").slice(2).join("\n"));
          const start = performance.now();
          let aborted = false;
          this.addEventListener("abort", () => {
            aborted = true;
          });
          this.addEventListener("loadend", () => {
            // From all the headers, so a header the page may not read logs no warning.
            const own = /^x-request-id:\s*(.+?)\s*$/im.exec(this.getAllResponseHeaders())?.[1];
            if (!aborted)
              done(k.method, k.t.path, k.rid ?? answerId(own), this.status, start, stack);
          });
        }
      } catch {}
      return send.call(this, body);
    };
  }
})();
