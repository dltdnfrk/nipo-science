/*
 * Settings › Models, driven through the real browser against the real listener.
 *
 * The assertions are on what a researcher sees and on what leaves the machine:
 * card text, status text, the DOM, and every byte of every API response the
 * page received. Internal element ids this suite also authored are not the
 * subject of any assertion here.
 */

import { axeSerious, expect, open, test, watchConsole } from "./local-harness.js";

// A key shaped like a real one. Nothing in the product may echo it back.
const CANARY = `sk-${"canary-9Qq7WwZzXx-never-render-me"}`;

test("provider cards render the real registry status and the local-only promise", async ({ app, local }) => {
  const errors = watchConsole(app);
  await open(app, local, "/settings/models");

  await expect(app.getByRole("heading", { level: 1, name: "모델 설정" })).toBeVisible();
  await expect(app.getByText("API 키는 이 컴퓨터에만 저장됩니다.")).toBeVisible();

  // The registry ships 13 providers; the page must show every one of them.
  const cards = app.locator(".provider-card");
  await expect(cards).toHaveCount(13);

  const anthropic = app.locator('[data-provider="anthropic"]');
  await expect(anthropic).toContainText("Claude (Anthropic)");
  await expect(anthropic).toContainText("설정 안 됨");

  const ollama = app.locator('[data-provider="ollama"]');
  await expect(ollama).toContainText("Ollama (local models)");
  await expect(ollama).toContainText("키 필요 없음");
  // A provider that needs no key must not offer a key control at all.
  await expect(ollama.getByRole("button", { name: /키/u })).toHaveCount(0);

  expect(errors).toEqual([]);
});

test("setting a key flips the card to 설정됨 and the key never enters the DOM or a response", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const card = app.locator('[data-provider="anthropic"]');
  await expect(card).toContainText("설정 안 됨");

  await card.getByRole("button", { name: "키 설정" }).click();
  const field = card.getByLabel("Claude (Anthropic) API 키");
  await expect(field).toHaveAttribute("type", "password");
  await field.fill(CANARY);
  await card.getByRole("button", { name: "키 저장" }).click();

  await expect(card).toContainText("설정됨");
  await expect(card).not.toContainText("설정 안 됨");

  // 1. The rendered page never carries the key.
  await expect(app.locator("body")).not.toContainText(CANARY);
  expect(await app.content()).not.toContain(CANARY);

  // 2. No input holds it either -- `toContainText` cannot see input values.
  const values = await app.evaluate(() =>
    [...document.querySelectorAll("input")].map((input) => input.value),
  );
  expect(values.join("|")).not.toContain(CANARY);

  // 3. No response the browser received carries it, including the PUT reply
  //    and the reload of the provider list that follows it.
  expect(local.apiResponseBodies.length).toBeGreaterThan(0);
  for (const body of local.apiResponseBodies) expect(body).not.toContain(CANARY);

  // 4. Nothing was written to browser storage.
  expect(
    await app.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ local: [], session: [] });

  // 5. Reading the provider back from the real API also discloses no value.
  const raw = await app.evaluate(
    async ([token, header]) => {
      const response = await fetch("/api/v1/providers/anthropic", { headers: { [header]: token } });
      return response.text();
    },
    [local.token, local.header] as const,
  );
  expect(raw).toContain('"configured"');
  expect(raw).not.toContain(CANARY);
});

test("clearing a key is a two-step action and returns the card to 설정 안 됨", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const card = app.locator('[data-provider="openai"]');

  await card.getByRole("button", { name: "키 설정" }).click();
  await card.getByLabel("OpenAI API 키").fill(CANARY);
  await card.getByRole("button", { name: "키 저장" }).click();
  await expect(card).toContainText("설정됨");

  const clear = card.getByRole("button", { name: "키 지우기" });
  await clear.click();
  // One click only arms the action; the card must not have changed yet.
  await expect(card).toContainText("설정됨");
  await card.getByRole("button", { name: /한 번 더 누르세요/u }).click();
  await expect(card).toContainText("설정 안 됨");
});

test("a key the registry refuses is reported by reason and is never echoed", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const card = app.locator('[data-provider="deepseek"]');
  await card.getByRole("button", { name: "키 설정" }).click();
  await card.getByLabel("DeepSeek API 키").fill(`  ${CANARY}  `);
  await card.getByRole("button", { name: "키 저장" }).click();

  const alert = app.getByRole("alert");
  await expect(alert).toContainText("키 앞뒤에 공백이 붙어 있습니다");
  await expect(alert).not.toContainText(CANARY);
  await expect(card).toContainText("설정 안 됨");
  for (const body of local.apiResponseBodies) expect(body).not.toContain(CANARY);
});

test("the composer picker marks exactly one default", async ({ app, local }) => {
  await open(app, local, "/settings/models");

  // A fresh install has no enabled models; the page says so instead of faking one.
  await expect(app.getByText("선택할 모델이 없습니다")).toBeVisible();

  await app.getByLabel("모델 추가").fill("anthropic:claude-sonnet-4");
  await app.getByRole("button", { name: "목록에 추가" }).click();
  await expect(app.locator('.composer-row[data-model="anthropic:claude-sonnet-4"]')).toBeVisible();

  await app.getByLabel("모델 추가").fill("openai:gpt-research");
  await app.getByRole("button", { name: "목록에 추가" }).click();
  await expect(app.locator(".composer-row")).toHaveCount(2);

  // Exactly one row is the default, and it is the one the researcher chose.
  await expect(app.locator('.composer-row[data-default="true"]')).toHaveCount(1);
  await expect(app.getByText("기본", { exact: true })).toHaveCount(1);

  await app.getByRole("button", { name: "openai:gpt-research을(를) 기본 모델로 지정" }).click();
  await expect(app.locator('.composer-row[data-default="true"]')).toHaveCount(1);
  await expect(
    app.locator('.composer-row[data-model="openai:gpt-research"][data-default="true"]'),
  ).toBeVisible();
  await expect(app.getByText("기본", { exact: true })).toHaveCount(1);

  // The server agrees, so this is not a client-side illusion.
  const picker = await app.evaluate(
    async ([token, header]) => {
      const response = await fetch("/api/v1/composer", { headers: { [header]: token } });
      return (await response.json()) as { default_model: string; models: { is_default: boolean }[] };
    },
    [local.token, local.header] as const,
  );
  expect(picker.default_model).toBe("openai:gpt-research");
  expect(picker.models.filter((item) => item.is_default)).toHaveLength(1);
});

test("a malformed model id is refused with the server's reason", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  await app.getByLabel("모델 추가").fill("no-separator-here");
  await app.getByRole("button", { name: "목록에 추가" }).click();
  await expect(app.getByRole("alert")).toContainText("`제공자:모델` 형식이어야 합니다");
});

test("the whole settings flow completes with the keyboard alone", async ({ app, local }) => {
  await open(app, local, "/settings/models");

  // Walk forward from the document until the first provider's key control has
  // focus. Nothing is clicked anywhere in this test.
  const target = app.locator('[data-provider="anthropic"]').getByRole("button", { name: "키 설정" });
  let reached = false;
  for (let step = 0; step < 60 && !reached; step += 1) {
    await app.keyboard.press("Tab");
    reached = await target.evaluate((node) => node === document.activeElement);
  }
  expect(reached).toBe(true);

  // Every control must show a visible focus ring, not just receive focus.
  const outline = await target.evaluate((node) => getComputedStyle(node).outlineWidth);
  expect(outline).not.toBe("0px");

  await app.keyboard.press("Enter");
  const field = app.locator('[data-provider="anthropic"]').getByLabel("Claude (Anthropic) API 키");
  await expect(field).toBeFocused();
  await app.keyboard.type(CANARY);
  await app.keyboard.press("Tab");
  await app.keyboard.press("Enter");

  await expect(app.locator('[data-provider="anthropic"]')).toContainText("설정됨");
  await expect(app.locator("body")).not.toContainText(CANARY);
});

test("every API request in this suite reached the real server", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const card = app.locator('[data-provider="mistral"]');
  await card.getByRole("button", { name: "키 설정" }).click();
  await card.getByLabel("Mistral API 키").fill(CANARY);
  await card.getByRole("button", { name: "키 저장" }).click();
  await expect(card).toContainText("설정됨");

  // The harness records anything it answered on the app's behalf. If a future
  // edit started stubbing the API, this list would stop being empty.
  expect(local.fulfilledByHarness).toEqual([]);
  expect(local.apiResponseBodies.length).toBeGreaterThan(0);
});

test("a request without the local credential is refused by the real guard", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const refusal = await app.evaluate(async () => {
    const response = await fetch("/api/v1/providers");
    return { status: response.status, body: await response.text() };
  });
  expect(refusal.status).toBe(401);
  expect(refusal.body).toContain("local_token_required");
});

test("Settings › Models has no serious or critical axe violation", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  const card = app.locator('[data-provider="anthropic"]');
  await card.getByRole("button", { name: "키 설정" }).click();
  await expect(card.getByLabel("Claude (Anthropic) API 키")).toBeVisible();

  const violations = await axeSerious(app);
  expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
});

test("long Korean text and a long digest never force a horizontal page scroll", async ({ app, local }) => {
  await open(app, local, "/settings/models");
  await app.getByLabel("모델 추가").fill(`anthropic:${"모델이름".repeat(24)}-${"f".repeat(96)}`);
  await app.getByRole("button", { name: "목록에 추가" }).click();
  await expect(app.locator(".composer-row").first()).toBeVisible();

  const overflow = await app.evaluate(() => ({
    doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    main: (() => {
      const main = document.getElementById("main-content");
      return main ? main.scrollWidth - main.clientWidth : 0;
    })(),
  }));
  expect(overflow.doc).toBeLessThanOrEqual(1);
  expect(overflow.main).toBeLessThanOrEqual(1);
});
