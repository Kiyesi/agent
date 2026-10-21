// A site and a Kiyesi endpoint for the snippet's tests. The site (port A)
// serves a test page and the snippet; a second site (port B) stands for
// another company's API; reports land in memory and are read back.
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

export type Seen = {
  reports: Record<string, unknown>[];
  headers: Record<string, string | undefined>[];
};

export function start(portA: number, portB: number) {
  const seen: Seen = { reports: [], headers: [] };
  const snippet = () => readFileSync(new URL("../dist/browser.js", import.meta.url));
  const page = (attrs: string, key: string) => `<!doctype html><html><head>
<script src="/browser.js" data-key="${key}" data-version="2.14.0" data-endpoint="http://localhost:${portA}" ${attrs}></script>
</head><body><input id="secret" value=""><p>Private page text</p></body></html>`;

  const body = (req: IncomingMessage) =>
    new Promise<string>((ok) => {
      let s = "";
      req.on("data", (c) => (s += c));
      req.on("end", () => ok(s));
    });

  const site = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://localhost:${portA}`);
    seen.headers.push({
      path: url.pathname,
      rid: req.headers["x-request-id"] as string | undefined,
    });
    if (url.pathname === "/browser.js")
      return res.writeHead(200, { "content-type": "text/javascript" }).end(snippet());
    if (url.pathname === "/v1/browser/errors") {
      seen.reports.push({
        ...JSON.parse(await body(req)),
        key: url.searchParams.get("k"),
        contentType: req.headers["content-type"],
      });
      return res.writeHead(202).end();
    }
    if (url.pathname.startsWith("/api/fail")) return res.writeHead(502).end("bad gateway");
    if (url.pathname === "/api/ok") return res.writeHead(200).end("ok");
    if (url.pathname === "/api/slow")
      return void setTimeout(() => res.writeHead(200).end("late"), 2000);
    if (url.pathname === "/page")
      return res
        .writeHead(200, { "content-type": "text/html" })
        .end(
          page(
            url.searchParams.get("attrs") ?? "",
            url.searchParams.get("key") ?? "ksk_test_key_abcdefghijklmnop",
          ),
        );
    res.writeHead(404).end();
  });
  // Another company's API: allows calls from the site, but not extra headers.
  const other = createServer((req, res) => {
    // The browser's preliminary OPTIONS check never carries the header.
    if (req.method !== "OPTIONS")
      seen.headers.push({
        path: `other${req.url}`,
        rid: req.headers["x-request-id"] as string | undefined,
      });
    const cors = {
      "access-control-allow-origin": `http://localhost:${portA}`,
      "access-control-allow-headers": "x-request-id",
    };
    if (req.method === "OPTIONS") return res.writeHead(204, cors).end();
    // An API that gives each answer an ID, and lets pages read it.
    if (req.url === "/given")
      return void setTimeout(
        () =>
          res
            .writeHead(200, {
              ...cors,
              "x-request-id": "given-by-the-api-0001",
              "access-control-expose-headers": "x-request-id",
            })
            .end("x"),
        600,
      );
    res.writeHead(req.url === "/fail" ? 503 : 200, cors).end("x");
  });
  site.listen(portA);
  other.listen(portB);
  return {
    seen,
    close: () => {
      site.close();
      other.close();
    },
  };
}
