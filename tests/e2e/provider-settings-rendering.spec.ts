import { expect, test, type Page } from "@playwright/test";
import { authenticateProduct, productOrigin } from "./product-auth.js";
import { providerRenderingAdapters, routeProviderRegistry } from "./provider-settings-fixture.js";

async function routeEmptyConnections(page: Page): Promise<void> {
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ connections: [] }),
  }));
}

test.beforeEach(async ({ page }) => {
  await authenticateProduct(page);
  await routeEmptyConnections(page);
});

test("server adapter metadata renders as literal text and controls actions", async ({ page }) => {
  await routeProviderRegistry(page, { adapters: providerRenderingAdapters });

  await page.goto(`${productOrigin}/settings/providers`);

  const openAiCard = page.locator('.provider-card[data-adapter-id="openai_codex"]');
  const glmCard = page.locator('.provider-card[data-adapter-id="zai_glm"]');
  const openAiDisabledReason = providerRenderingAdapters[0].disabled_reason;
  if (openAiDisabledReason === null) {
    throw new Error("Adversarial OpenAI fixture must be disabled");
  }
  await expect(openAiCard.getByRole("heading")).toHaveText(providerRenderingAdapters[0].name);
  await expect(openAiCard.locator(".status")).toHaveText(providerRenderingAdapters[0].availability_label);
  await expect(openAiCard).toContainText(openAiDisabledReason);
  await expect(openAiCard.getByRole("button")).toHaveCount(0);
  await expect(glmCard.locator(".status")).toHaveText(providerRenderingAdapters[1].availability_label);
  await expect(glmCard.getByRole("button", { name: /연결/u })).toHaveCount(1);
  await expect(page.locator("[data-provider-injection]")).toHaveCount(0);
});

test("malformed registry response fails closed without provider actions", async ({ page }) => {
  await routeProviderRegistry(page, {
    adapters: [{ id: "openai_codex", connectable: true }],
  });

  await page.goto(`${productOrigin}/settings/providers`);

  await expect(page.getByRole("alert")).toContainText("제공자 레지스트리 응답을 확인할 수 없습니다.");
  await expect(page.getByRole("heading", { name: "서버 응답을 확인할 수 없습니다" })).toBeVisible();
  await expect(page.locator('[data-action^="provider-"]')).toHaveCount(0);
});

test("provider cards apply status styling and collapse to one mobile column", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await routeProviderRegistry(page, { adapters: providerRenderingAdapters });
  await page.goto(`${productOrigin}/settings/providers`);

  const grid = page.locator(".provider-grid");
  const desktop = await grid.evaluate((element) => ({
    columns: getComputedStyle(element).gridTemplateColumns.split(" ").length,
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  const phraseWhiteSpace = await page.locator(".phrase").first().evaluate(
    (element) => getComputedStyle(element).whiteSpace,
  );
  const attentionBorder = await page.locator('.provider-card[data-adapter-id="openai_codex"]').evaluate(
    (element) => getComputedStyle(element).borderTopColor,
  );
  const positiveBorder = await page.locator('.provider-card[data-adapter-id="zai_glm"]').evaluate(
    (element) => getComputedStyle(element).borderTopColor,
  );
  expect(desktop.columns).toBeGreaterThan(1);
  expect(desktop.overflow).toBeLessThanOrEqual(1);
  expect(phraseWhiteSpace).toBe("nowrap");
  expect(positiveBorder).not.toBe(attentionBorder);

  await page.setViewportSize({ width: 375, height: 812 });
  const mobile = await grid.evaluate((element) => ({
    columns: getComputedStyle(element).gridTemplateColumns.split(" ").length,
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect(mobile.columns).toBe(1);
  expect(mobile.overflow).toBeLessThanOrEqual(1);
});
