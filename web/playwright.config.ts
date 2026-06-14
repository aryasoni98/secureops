import { defineConfig, devices } from "@playwright/test";

// Playwright config for the SecureOps wizard E2E (PRODUCT.md Phase 8 exit).
// Spins up `vite preview` against the built SPA and points the API proxy at
// the local secureops-api. Override SECUREOPS_API for CI clusters.

export default defineConfig({
  testDir: "./tests",
  // Live-only specs (need `npm run dev` + a running secureops-api/license-server)
  // run via playwright.live.config.ts, never in CI's headless preview job.
  testIgnore: "**/live-*.spec.ts",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: process.env.SECUREOPS_WEB || "http://127.0.0.1:4173",
    headless: true,
  },
  webServer: {
    command: "npm run preview -- --host 127.0.0.1 --port 4173 --strictPort",
    url: "http://127.0.0.1:4173",
    timeout: 60_000,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
