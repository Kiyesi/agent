// The snippet in a real browser: what it reports, what it never sends,
// the request IDs it adds, and its manners.
import { expect, test } from "@playwright/test";
import { start } from "./server.ts";

const A = 18731;
const B = 18732;
let s: ReturnType<typeof start>;

test.beforeAll(() => {
  s = start(A, B);
});
test.afterAll(() => s.close());
test.beforeEach(() => {
  s.seen.reports.length = 0;
  s.seen.headers.length = 0;
});

const reports = () => s.seen.reports;
const waitFor = async (n: number) =>
  expect.poll(() => reports().length, { timeout: 5000 }).toBeGreaterThanOrEqual(n);

test("reports an uncaught error with its stack, without the page's query or content", async ({
  page,
  context,
}) => {
  await context.addCookies([
    { name: "session", value: "cookie-value-never-sent", url: `http://localhost:${A}` },
  ]);
  await page.goto(`http://localhost:${A}/page?token=secret-in-query#frag`);
  await page.fill("#secret", "typed-password-never-sent");
  await page.evaluate(() => {
    setTimeout(() => {
      (undefined as unknown as { amount: number }).amount;
    });
  });
  await waitFor(1);
  const r = reports()[0] as Record<string, string>;
  expect(r).toMatchObject({
    kind: "error",
    type: "TypeError",
    version: "2.14.0",
    key: "ksk_test_key_abcdefghijklmnop",
    page: `http://localhost:${A}/page`,
    contentType: "text/plain;charset=UTF-8",
  });
  expect(r.message).toMatch(/amount/);
  expect(r.stack).toMatch(/:\d+:\d+/);
  const all = JSON.stringify(reports());
  for (const never of [
    "cookie-value-never-sent",
    "typed-password-never-sent",
    "Private page text",
    "secret-in-query",
    "frag",
  ])
    expect(all).not.toContain(never);
});

test("reports an unhandled rejection", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page`);
  await page.evaluate(() => void Promise.reject(new RangeError("the quantity is out of range")));
  await waitFor(1);
  expect(reports()[0]).toMatchObject({
    kind: "rejection",
    type: "RangeError",
    message: "the quantity is out of range",
  });
});

test("tags the site's own requests with an ID and reports a 5xx with it", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page`);
  await page.evaluate(async () => {
    await fetch("/api/ok?x=1");
    await fetch("/api/fail?card=4111", { method: "POST" });
  });
  await waitFor(1);
  const r = reports()[0] as Record<string, string>;
  expect(r).toMatchObject({
    kind: "request",
    type: "Request failed",
    message: "POST /api/fail returned 502",
  });
  const sentId = s.seen.headers.find((h) => h.path === "/api/fail")?.rid;
  expect(sentId).toMatch(/^[0-9a-f-]{20,}$/);
  // The same ID the web server logged, so the error meets the backend's line.
  expect(r.requestId).toBe(sentId);
  expect(s.seen.headers.find((h) => h.path === "/api/ok")?.rid).toBeTruthy();
  expect(reports()).toHaveLength(1);
});

test("reports how long a slow request of the site's own took, for its trace", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page?attrs=${encodeURIComponent('data-slow-ms="300"')}`);
  await page.evaluate(async () => {
    await fetch("/api/ok");
    await fetch("/api/slow?q=1");
    const x = new XMLHttpRequest();
    x.open("GET", "/api/slow");
    x.send();
    await new Promise((r) => x.addEventListener("loadend", r));
  });
  await waitFor(2);
  const timings = reports().filter((r) => r.kind === "timing") as Record<string, unknown>[];
  expect(timings).toHaveLength(2);
  for (const t of timings) {
    expect(t).toMatchObject({
      type: "Slow request",
      method: "GET",
      path: "/api/slow",
      status: 200,
    });
    expect(t.ms).toBeGreaterThanOrEqual(1900);
    expect(t.requestId).toBe(
      s.seen.headers.filter((h) => h.path === "/api/slow").map((h) => h.rid)[timings.indexOf(t)],
    );
  }
  // A fast request is not reported, and a failed one carries its figures.
  await page.evaluate(() => fetch("/api/fail", { method: "POST" }));
  await waitFor(3);
  expect(reports().filter((r) => r.path === "/api/ok")).toEqual([]);
  expect(reports().at(-1)).toMatchObject({ kind: "request", method: "POST", status: 502 });
});

test("uses the ID an answer carries for a request it did not tag", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page?attrs=${encodeURIComponent('data-slow-ms="300"')}`);
  await page.evaluate(async (b) => {
    await fetch(`http://localhost:${b}/given`);
    const x = new XMLHttpRequest();
    x.open("GET", `http://localhost:${b}/given`);
    x.send();
    await new Promise((r) => x.addEventListener("loadend", r));
  }, B);
  await waitFor(2);
  // Not tagged: no header was added, so no preflight was needed.
  expect(s.seen.headers.filter((h) => h.path === "other/given").map((h) => h.rid)).toEqual([
    undefined,
    undefined,
  ]);
  expect(reports().map((r) => [r.kind, r.requestId])).toEqual([
    ["timing", "given-by-the-api-0001"],
    ["timing", "given-by-the-api-0001"],
  ]);
});

test("leaves other sites' requests alone unless listed", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page`);
  await page.evaluate(async (b) => {
    await fetch(`http://localhost:${b}/fail`);
  }, B);
  await waitFor(1);
  expect(s.seen.headers.find((h) => h.path === "other/fail")?.rid).toBeUndefined();
  expect(reports()[0]).toMatchObject({ message: "GET /fail returned 503" });
  expect((reports()[0] as { requestId?: string }).requestId).toBeUndefined();

  s.seen.headers.length = 0;
  await page.goto(
    `http://localhost:${A}/page?attrs=${encodeURIComponent(`data-trace-origins="http://localhost:${B}"`)}`,
  );
  await page.evaluate(async (b) => {
    await fetch(`http://localhost:${b}/ok`);
  }, B);
  await expect.poll(() => s.seen.headers.find((h) => h.path === "other/ok")?.rid).toBeTruthy();
});

test("XMLHttpRequest failures too; a request the page cancels is not one", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page`);
  await page.evaluate(() => {
    const x = new XMLHttpRequest();
    x.open("GET", "/api/fail");
    x.send();
    const y = new XMLHttpRequest();
    y.open("GET", "/api/slow");
    y.send();
    y.abort();
    void fetch("/api/slow", { signal: AbortSignal.timeout(50) }).catch(() => {});
  });
  await waitFor(1);
  await page.waitForTimeout(500);
  expect(reports().map((r) => r.message)).toEqual(["GET /api/fail returned 502"]);
  expect(s.seen.headers.find((h) => h.path === "/api/fail")?.rid).toBeTruthy();
});

test("sends each error once, and at most ten reports a page", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page`);
  await page.evaluate(() => {
    for (let i = 0; i < 3; i++)
      setTimeout(() => {
        throw new Error("the same error");
      });
    for (let i = 0; i < 20; i++)
      setTimeout(() => {
        throw new Error(`error number ${i}`);
      });
  });
  await waitFor(10);
  await page.waitForTimeout(500);
  expect(reports()).toHaveLength(10);
  expect(reports().filter((r) => r.message === "the same error")).toHaveLength(1);
});

test("without a valid key it does nothing, and it never breaks the page", async ({ page }) => {
  await page.goto(`http://localhost:${A}/page?key=nope`);
  const ok = await page.evaluate(async () => {
    setTimeout(() => {
      throw new Error("not reported");
    });
    const r = await fetch("/api/ok");
    return r.ok;
  });
  expect(ok).toBe(true);
  await page.waitForTimeout(500);
  expect(reports()).toHaveLength(0);
});
