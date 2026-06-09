import { expect, test } from "@playwright/test";

// First-run wizard E2E (PRODUCT.md Phase 8 exit criterion).
// Mocks the API so the test can run without a live backend. Verifies:
//   1. Unauthed visitor is redirected to /license.
//   2. License activation stores the token and lands on /setup/llm-keys.
//   3. The wizard flows step-by-step into the dashboard.

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/license/activate", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        tier: "enterprise",
        expiry: 9999999999,
        features: ["bughunt", "sso"],
        token: "test-token",
      }),
    });
  });
  await page.route("**/api/v1/license", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ tier: "enterprise", expiry: 9999999999, features: [] }),
    });
  });
  await page.route("**/api/v1/findings*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ findings: [], count: 0 }),
    });
  });
  await page.route("**/api/v1/scans", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ jobId: "test-scan", status: "queued" }),
    });
  });
});

test("first-run wizard end-to-end", async ({ page, context }) => {
  await context.clearCookies();
  await page.addInitScript(() => localStorage.clear());

  await page.goto("/findings");
  await expect(page).toHaveURL(/\/license/);

  await page.getByTestId("license-key").fill("dummy");
  await page.getByRole("button", { name: "Activate" }).click();

  await expect(page).toHaveURL(/\/setup\/llm-keys/);
  await page.getByPlaceholder("sk-...").fill("sk-test");
  await page.getByRole("button", { name: "Save & test" }).click();

  await expect(page).toHaveURL(/\/setup\/cloud/);
  await page.getByPlaceholder(/arn:aws:iam/).fill("arn:aws:iam::123:role/SecureOpsReader");
  await page.getByRole("button", { name: "Save & continue" }).click();

  await expect(page).toHaveURL(/\/setup\/scan/);
  await page.getByRole("button", { name: "Run scan" }).click();
  await expect(page.locator("text=job: test-scan")).toBeVisible();

  await page.getByRole("button", { name: /Continue to dashboard/ }).click();
  await expect(page).toHaveURL(/\/findings/);
  await expect(page.locator("h1", { hasText: "Findings" })).toBeVisible();
});
