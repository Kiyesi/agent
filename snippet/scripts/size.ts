// The guide's budget: the snippet stays under 5 KB compressed. The build
// fails if it grows past it. (A few lines here instead of size-limit, so
// the check adds no dependency.)
import { readFileSync } from "node:fs";
import { brotliCompressSync, gzipSync } from "node:zlib";

const LIMIT = 5 * 1024;
const code = readFileSync(new URL("../dist/browser.js", import.meta.url));
const gz = gzipSync(code, { level: 9 }).length;
const br = brotliCompressSync(code).length;
console.log(`browser.js: ${code.length} bytes, ${gz} gzipped, ${br} with brotli (limit ${LIMIT})`);
if (gz > LIMIT) {
  console.error("The snippet is over its 5 KB budget.");
  process.exit(1);
}
