import { expect, test } from "@playwright/test";
import { execSync } from "node:child_process";

// Live E2E against local vite (5173) + secureops-api (8080). No API mocks.

import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const LICENSE_KEY = execSync(
  "./target/release/secureops-license-server mint --dev --tenant local --tier enterprise --days 365 2>/dev/null | grep '^eyJ'",
  { encoding: "utf8", cwd: REPO_ROOT },
).trim();

test.describe.configure({ mode: "serial" });

test("live license activation and wizard", async ({ page }) => {
  await page.goto("http://127.0.0.1:5173/license");
  await page.screenshot({ path: "test-results/live-01-license-page.png", fullPage: true });

  await page.getByTestId("license-key").fill(LICENSE_KEY);
  await page.getByRole("button", { name: "Activate" }).click();

  // Wait for success message or error
  await page.waitForTimeout(2000);
  await page.screenshot({ path: "test-results/live-02-after-activate.png", fullPage: true });

  const msg = await page.locator("p.text-sm.text-slate-300").textContent();
  console.log("UI message:", msg);

  if (msg?.includes("ApiError") || msg?.includes("failed")) {
    throw new Error(`License activation failed in UI: ${msg}`);
  }

  await expect(page).toHaveURL(/\/setup\/llm-keys/, { timeout: 10_000 });
  await page.screenshot({ path: "test-results/live-03-llm-keys.png", fullPage: true });

  await page.getByPlaceholder("sk-...").fill("sk-test-local");
  await page.getByRole("button", { name: "Save & test" }).click();
  await expect(page).toHaveURL(/\/setup\/cloud/);

  await page.getByPlaceholder(/arn:aws:iam/).fill("arn:aws:iam::368887614602:user/arya@studiomgmt.co");
  await page.getByRole("button", { name: "Save & continue" }).click();
  await expect(page).toHaveURL(/\/setup\/scan/);
  await page.screenshot({ path: "test-results/live-04-scan.png", fullPage: true });

  await page.getByRole("button", { name: "Run scan" }).click();
  await expect(page.locator("text=/job:/")).toBeVisible({ timeout: 15_000 });

  await page.getByRole("button", { name: /Continue to dashboard/ }).click();
  await expect(page).toHaveURL(/\/findings/);
  await page.screenshot({ path: "test-results/live-05-findings.png", fullPage: true });
});
