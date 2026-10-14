// Copies the built snippet to public/v1/browser.js, the address sites load.
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync(new URL("../public/v1/", import.meta.url), { recursive: true });
copyFileSync(
  new URL("../dist/browser.js", import.meta.url),
  new URL("../public/v1/browser.js", import.meta.url),
);
