import { defineConfig } from "vitest/config";

// Vitest (unit) runs ONLY under `src/**`. Playwright E2E lives in `tests/`
// and is driven via `npm run e2e`.
export default defineConfig({
  test: {
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["tests/**", "node_modules/**", "dist/**"],
    environment: "node",
  },
});
