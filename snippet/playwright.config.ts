import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "test",
  timeout: 30_000,
  workers: 1,
  reporter: [["list"]],
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
