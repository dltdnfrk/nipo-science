import { expect, test, type Request } from "@playwright/test";
import { authenticateProduct, productFixtureCredential, productOrigin } from "./product-auth.js";
import { routeProviderRegistry } from "./provider-settings-fixture.js";

const oauthState = "opaque-oauth-state-do-not-render";
const uuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

test.beforeEach(async ({ page }) => {
  await authenticateProduct(page);
  await routeProviderRegistry(page);
});

test("connect lifecycle uses server capability and keeps OAuth state out of the DOM", async ({ page }) => {
  let mutation: Request | undefined;
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ connections: [] }),
      });
    }
    mutation = request;
    return route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        authorization_url: "https://provider.example.test/authorize?state=browser-safe",
        device_instruction: null,
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        flow: "callback",
        revision: "0",
        state: oauthState,
      }),
    });
  });

  await page.goto(`${productOrigin}/settings/providers`);
  const openAiCard = page.locator('[data-adapter-id="openai_codex"]');
  await openAiCard.getByRole("button", { name: /OpenAI .* 연결/u }).click();

  await expect.poll(() => mutation?.method()).toBe("POST");
  if (!mutation) throw new Error("Provider connect request was not observed");
  expect(mutation.postData()).toBe(JSON.stringify({
    adapter_id: "openai_codex",
    flow: "callback",
    redirect_uri: "/settings/providers",
  }));
  const headers = await mutation.allHeaders();
  expect(headers["idempotency-key"]).toMatch(uuidV4Pattern);
  expect(headers["x-csrf-token"]).toBe((await productFixtureCredential()).csrf);
  await expect(page.locator("#provider-authorization-link")).toHaveAttribute(
    "href",
    "https://provider.example.test/authorize?state=browser-safe",
  );
  await expect(page.locator("body")).not.toContainText(oauthState);
  expect(await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }))).toEqual({ local: [], session: [] });
  await expect(page.locator('input[type="password"], input[name*="key" i], [data-token]')).toHaveCount(0);
});

test("callback completion scrubs the state query and sends the canonical mutation", async ({ page }) => {
  let completion: Request | undefined;
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ connections: [] }),
  }));
  await page.route(`${productOrigin}/api/v1/provider-connections/oauth/complete`, (route) => {
    completion = route.request();
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });

  await page.goto(`${productOrigin}/settings/providers?state=callback-state-sentinel`);

  await expect.poll(() => completion?.method()).toBe("POST");
  if (!completion) throw new Error("Provider callback request was not observed");
  expect(completion.postData()).toBe(JSON.stringify({
    state: "callback-state-sentinel",
    flow: "callback",
    redirect_uri: "/settings/providers",
  }));
  expect(new URL(page.url()).search).toBe("");
  const headers = await completion.allHeaders();
  expect(headers["idempotency-key"]).toMatch(uuidV4Pattern);
  expect(headers["x-csrf-token"]).toBe((await productFixtureCredential()).csrf);
});

test("duplicate callback state fails closed before completion", async ({ page }) => {
  let completionCount = 0;
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ connections: [] }),
  }));
  await page.route(`${productOrigin}/api/v1/provider-connections/oauth/complete`, (route) => {
    completionCount += 1;
    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });

  await page.goto(`${productOrigin}/settings/providers?state=first&state=second`);

  await expect(page.getByRole("alert")).toContainText("제공자 인증 상태가 올바르지 않습니다.");
  expect(completionCount).toBe(0);
  expect(new URL(page.url()).search).toBe("");
});

test("model mutation uses the selected model and server revision", async ({ page }) => {
  let mutation: Request | undefined;
  const connection = {
    id: "connection-openai",
    adapter_id: "openai_codex",
    account: { id: "researcher@example.invalid" },
    models: ["gpt-research", "gpt-research-next"],
    selected_model: "gpt-research",
    status: "healthy",
    health: "healthy",
    qualification: { cleanup_verified: true, live: true },
    revision: "revision-from-server-42",
  };
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ connections: [connection] }),
  }));
  await page.route(`${productOrigin}/api/v1/provider-connections/${connection.id}/model`, (route) => {
    mutation = route.request();
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(connection) });
  });

  await page.goto(`${productOrigin}/settings/providers`);
  await page.getByRole("combobox", { name: /선택 모델/u }).selectOption("gpt-research-next");
  await page.getByRole("button", { name: "모델 저장" }).click();

  await expect.poll(() => mutation?.method()).toBe("POST");
  if (!mutation) throw new Error("Provider model request was not observed");
  expect(mutation.postData()).toBe(JSON.stringify({ model_id: "gpt-research-next" }));
  const headers = await mutation.allHeaders();
  expect(headers["if-match"]).toBe("revision-from-server-42");
  expect(headers["idempotency-key"]).toMatch(uuidV4Pattern);
  expect(headers["x-csrf-token"]).toBe((await productFixtureCredential()).csrf);
});
