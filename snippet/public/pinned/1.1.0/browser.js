"use strict";
(() => {
    var _a, _b;
    const w = window;
    const doc = document;
    if (w.__kiyesi)
        return;
    w.__kiyesi = true;
    const script = doc.currentScript;
    const attr = (name) => { var _a; return (_a = script === null || script === void 0 ? void 0 : script.getAttribute(name)) !== null && _a !== void 0 ? _a : ""; };
    const key = attr("data-key");
    if (!/^ksk_[A-Za-z0-9_-]{20,}$/.test(key))
        return;
    const version = attr("data-version").slice(0, 64);
    const endpoint = `${attr("data-endpoint") || "https://api.kiyesi.dev"}/v1/browser/errors?k=${encodeURIComponent(key)}`;
    const traced = new Set([location.origin]);
    for (const o of attr("data-trace-origins").split(/[\s,]+/)) {
        try {
            if (o)
                traced.add(new URL(o).origin);
        }
        catch { }
    }
    const slowMs = Number(attr("data-slow-ms")) || 1000;
    const MAX = 10;
    let sent = 0;
    let timings = 0;
    const seen = new Set();
    const clean = (u) => {
        try {
            const x = new URL(u, location.href);
            return x.origin + x.pathname;
        }
        catch {
            return "";
        }
    };
    const M = "[masked]";
    const maskStack = (s) => s
        .replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, M)
        .replace(/\b(bearer|basic)\s+[\w.~+/=-]{8,}/gi, `$1 ${M}`)
        .replace(/((?:password|passwd|pwd|secret|token|api[_-]?key|auth|session|cookie)[\w.-]*["']?\s*[:=]\s*["']?)[^\s"',;&]{3,}/gi, `$1${M}`);
    const mask = (s) => maskStack(s).replace(/[\w-]{24,}/g, (t) => (/\d/.test(t) && /[a-z]/i.test(t) ? M : t));
    const stackOf = (s) => typeof s === "string" ? s.replace(/\?[^\s):]*/g, "").slice(0, 8000) : "";
    const RID = /^[A-Za-z0-9_-]{8,64}$/;
    const answerId = (v) => (v && RID.test(v) ? v : undefined);
    const id = () => {
        try {
            return crypto.randomUUID();
        }
        catch {
            return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 14)}`;
        }
    };
    function report(r) {
        var _a;
        try {
            if (r.kind === "timing") {
                if (timings++ >= 20)
                    return;
            }
            else {
                if (sent >= MAX)
                    return;
                const print = `${r.type}|${r.message}|${r.stack.slice(0, 300)}`;
                if (seen.has(print))
                    return;
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
            if (!((_a = navigator.sendBeacon) === null || _a === void 0 ? void 0 : _a.call(navigator, endpoint, body))) {
                void (origFetch === null || origFetch === void 0 ? void 0 : origFetch(endpoint, {
                    method: "POST",
                    body,
                    keepalive: true,
                    mode: "no-cors",
                    credentials: "omit",
                    headers: { "content-type": "text/plain" },
                }).catch(() => { }));
            }
        }
        catch { }
    }
    w.addEventListener("error", (e) => {
        var _a, _b;
        if (!(e instanceof ErrorEvent))
            return;
        const err = e.error;
        report({
            kind: "error",
            type: (err === null || err === void 0 ? void 0 : err.name) || "Error",
            message: String((_b = (_a = err === null || err === void 0 ? void 0 : err.message) !== null && _a !== void 0 ? _a : e.message) !== null && _b !== void 0 ? _b : ""),
            stack: stackOf(err === null || err === void 0 ? void 0 : err.stack) || (e.filename ? `at ${clean(e.filename)}:${e.lineno}:${e.colno}` : ""),
        });
    });
    w.addEventListener("unhandledrejection", (e) => {
        const r = e.reason;
        const err = r instanceof Error ? r : null;
        report({
            kind: "rejection",
            type: (err === null || err === void 0 ? void 0 : err.name) || "UnhandledRejection",
            message: err ? err.message : String(r).slice(0, 1000),
            stack: stackOf(err === null || err === void 0 ? void 0 : err.stack),
        });
    });
    const target = (u) => {
        var _a;
        try {
            const x = new URL(u, location.href);
            return {
                path: x.pathname,
                own: traced.has(x.origin),
                ours: x.href.startsWith((_a = endpoint.split("?")[0]) !== null && _a !== void 0 ? _a : ""),
            };
        }
        catch {
            return { path: "", own: false, ours: false };
        }
    };
    const done = (method, path, rid, status, start, stack) => {
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
    const origFetch = (_a = w.fetch) === null || _a === void 0 ? void 0 : _a.bind(w);
    if (origFetch) {
        w.fetch = (input, init) => {
            var _a, _b, _c;
            let t = { path: "", own: false, ours: true };
            let method = "GET";
            let rid;
            let stack = "";
            const start = performance.now();
            try {
                const url = input instanceof Request ? input.url : String(input);
                t = target(url);
                method = (init === null || init === void 0 ? void 0 : init.method) || (input instanceof Request ? input.method : "GET");
                if (!t.ours) {
                    stack = stackOf((_a = new Error().stack) === null || _a === void 0 ? void 0 : _a.split("\n").slice(2).join("\n"));
                    if (t.own) {
                        rid = id();
                        const headers = new Headers((_b = init === null || init === void 0 ? void 0 : init.headers) !== null && _b !== void 0 ? _b : (input instanceof Request ? input.headers : undefined));
                        if (!headers.has("x-request-id"))
                            headers.set("x-request-id", rid);
                        else
                            rid = (_c = headers.get("x-request-id")) !== null && _c !== void 0 ? _c : rid;
                        init = { ...init, headers };
                    }
                }
            }
            catch { }
            return origFetch(input, init).then((res) => {
                if (!t.ours)
                    done(method, t.path, rid !== null && rid !== void 0 ? rid : answerId(res.headers.get("x-request-id")), res.status, start, stack);
                return res;
            }, (err) => {
                const gaveUp = err instanceof DOMException &&
                    (err.name === "AbortError" || err.name === "TimeoutError");
                if (!t.ours && !gaveUp)
                    done(method, t.path, rid, 0, start, stack);
                throw err;
            });
        };
    }
    const X = (_b = w.XMLHttpRequest) === null || _b === void 0 ? void 0 : _b.prototype;
    if (X) {
        const open = X.open;
        const send = X.send;
        X.open = function (method, url, ...rest) {
            try {
                this.__k = { method, t: target(String(url)) };
            }
            catch { }
            return open.call(this, method, url, ...rest);
        };
        X.send = function (body) {
            var _a;
            try {
                const k = this.__k;
                if (k && !k.t.ours) {
                    if (k.t.own) {
                        k.rid = id();
                        this.setRequestHeader("X-Request-Id", k.rid);
                    }
                    const stack = stackOf((_a = new Error().stack) === null || _a === void 0 ? void 0 : _a.split("\n").slice(2).join("\n"));
                    const start = performance.now();
                    let aborted = false;
                    this.addEventListener("abort", () => {
                        aborted = true;
                    });
                    this.addEventListener("loadend", () => {
                        var _a, _b;
                        const own = (_a = /^x-request-id:\s*(.+?)\s*$/im.exec(this.getAllResponseHeaders())) === null || _a === void 0 ? void 0 : _a[1];
                        if (!aborted)
                            done(k.method, k.t.path, (_b = k.rid) !== null && _b !== void 0 ? _b : answerId(own), this.status, start, stack);
                    });
                }
            }
            catch { }
            return send.call(this, body);
        };
    }
})();
