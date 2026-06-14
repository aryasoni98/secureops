import { defineConfig, devices } from "@playwright/test";

// Live local test: assumes `npm run dev` (5173) + secureops-api (8080) already running.
export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:5173",
    headless: true,
    screenshot: "on",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
