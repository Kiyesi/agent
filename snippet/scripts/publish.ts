// Copies the built snippet to public/v1/browser.js, the address sites load,
// and to public/pinned/<version>/browser.js, a copy that never changes, for
// sites that pin it with a Subresource Integrity hash. The pinned copies
// are kept in git, so every version stays served after each deploy. A
// version's copy is never replaced: if the snippet changed, raise "version"
// in snippet/package.json.
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const at = (p: string) => new URL(p, import.meta.url);
const { version } = JSON.parse(readFileSync(at("../package.json"), "utf8")) as { version: string };
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`snippet/package.json has no version such as 1.0.0 (it has ${version}).`);
  process.exit(1);
}
const code = readFileSync(at("../dist/browser.js"));

mkdirSync(at("../public/v1/"), { recursive: true });
copyFileSync(at("../dist/browser.js"), at("../public/v1/browser.js"));

const pinned = at(`../public/pinned/${version}/browser.js`);
if (existsSync(pinned)) {
  if (!readFileSync(pinned).equals(code)) {
    console.error(
      `The snippet changed, but public/pinned/${version}/browser.js is already published and never changes. Raise "version" in snippet/package.json.`,
    );
    process.exit(1);
  }
} else {
  mkdirSync(at(`../public/pinned/${version}/`), { recursive: true });
  writeFileSync(pinned, code);
}

const integrity = `sha384-${createHash("sha384").update(code).digest("base64")}`;
console.log(`pinned: https://cdn.kiyesi.dev/pinned/${version}/browser.js`);
console.log(`integrity: ${integrity}`);
