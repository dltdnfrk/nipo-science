import { createHash } from "node:crypto";
import { expect, test, type Locator, type Page } from "@playwright/test";

const appOrigin = "http://127.0.0.1:18765";

async function tabTo(page: Page, target: Locator): Promise<void> {
  for (let step = 0; step < 64; step += 1) {
    if (await target.evaluate((node) => node === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error("Target was not reachable with keyboard Tab navigation");
}

test.beforeEach(async ({ context }) => {
  await context.addCookies([
    {
      name: "artifact_test_principal",
      value: "playwright-test-principal",
      url: appOrigin,
      httpOnly: true,
      sameSite: "Strict",
    },
  ]);
});

test("keyboard flow preserves explicit versions and isolated preview", async ({ page }, testInfo) => {
  const previewCookies: Array<string | undefined> = [];
  page.on("request", (request) => {
    if (new URL(request.url()).hostname === "localhost") {
      previewCookies.push(request.headers().cookie);
    }
  });

  await page.goto("/artifacts");
  await expect(page.getByRole("heading", { name: "아티팩트 라이브러리" })).toBeVisible();
  await expect(page.locator(".artifact-library-item")).toHaveCount(3);

  const spectrumLink = page.getByRole("link", { name: "normalized.csv" });
  await tabTo(page, spectrumLink);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/artifacts\/artifact-spectrum$/);

  const versionOne = page.getByRole("button", { name: "v1 보기" }).first();
  await tabTo(page, versionOne);
  await page.keyboard.press("Enter");
  await expect(page.locator('tr[aria-current="true"]')).toContainText("v1");
  await expect(
    page.locator(
      '[data-action="select-version"][data-version-id="artifact-spectrum-v1"]:visible',
    ),
  ).toBeFocused();

  const versionTwo = page.getByRole("button", { name: "v2 보기" }).filter({ visible: true });
  await tabTo(page, versionTwo);
  await page.keyboard.press("Enter");
  await expect(page.locator('tr[aria-current="true"]')).toContainText("v2");
  await expect(
    page.locator(
      '[data-action="select-version"][data-version-id="artifact-spectrum-v2"]:visible',
    ),
  ).toBeFocused();

  const versionOneAgain = page.getByRole("button", { name: "v1 보기" }).filter({ visible: true });
  await tabTo(page, versionOneAgain);
  await page.keyboard.press("Enter");
  await expect(page.locator('tr[aria-current="true"]')).toContainText("v1");

  const attach = page.getByRole("button", { name: "세션에 연결" });
  await tabTo(page, attach);
  await page.keyboard.press("Enter");
  await expect(page.getByText("session-demo", { exact: true })).toBeVisible();

  const detach = page.getByRole("button", { name: "세션 연결 해제" });
  await expect(detach).toBeFocused();
  await tabTo(page, detach);
  await page.keyboard.press("Enter");
  await expect(page.getByText("없음", { exact: true })).toBeVisible();
  await expect(attach).toBeFocused();

  const downloadPromise = page.waitForEvent("download");
  const downloadLink = page.getByRole("link", { name: "검증된 Version 다운로드" });
  await tabTo(page, downloadLink);
  await page.keyboard.press("Enter");
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("normalized.csv");

  const detail = await page.request.get(
    `${appOrigin}/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1`,
  );
  const detailBody = await detail.json();
  const previewUrl = String(detailBody.preview_url);
  const preview = await page.request.get(previewUrl);
  const previewBytes = await preview.body();
  expect(preview.headers()["content-security-policy"]).toBe("default-src 'none'");
  expect(preview.headers()["x-content-type-options"]).toBe("nosniff");
  expect(preview.headers()["set-cookie"]).toBeUndefined();
  expect(createHash("sha256").update(previewBytes).digest("hex")).toBe(
    detailBody.selected.sha256,
  );
  await expect.poll(() => previewCookies.length).toBeGreaterThan(0);
  expect(previewCookies.every((cookie) => cookie === undefined)).toBe(true);

  const editor = page.locator("#artifact-version-content");
  const nextVersionNumber = (await page.locator(".artifact-table tbody tr").count()) + 1;
  await tabTo(page, editor);
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type("wavelength,intensity\n500,22\n");
  const create = page.getByRole("button", { name: "새 Version 생성" });
  await tabTo(page, create);
  await page.keyboard.press("Enter");
  await expect(page.locator('tr[aria-current="true"]')).toContainText(
    `v${nextVersionNumber}`,
  );
  await page.screenshot({
    path: `test-results/artifact-library-${testInfo.project.name}.png`,
    fullPage: true,
  });
});

test("library opens passive CSV PNG and PDF histories", async ({ page }) => {
  await page.goto("/artifacts");
  for (const [name, artifactId] of [
    ["normalized.csv", "artifact-spectrum"],
    ["preview.png", "artifact-image"],
    ["analysis.pdf", "artifact-report"],
  ]) {
    await tabTo(page, page.getByRole("link", { name }));
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`/artifacts/${artifactId}$`));
    await expect(page.getByRole("heading", { name: "아티팩트", exact: true })).toBeVisible();
    await page.goto("/artifacts");
  }
});

test("latest overlapping Version selection wins", async ({ page }) => {
  let releaseDelayedResponse = (): void => {};
  const delayedResponse = new Promise<void>((resolve) => {
    releaseDelayedResponse = resolve;
  });
  let delayedRequestSeen = false;
  let latestRequestSeen = false;
  await page.route("**/versions/artifact-spectrum-v1", async (route) => {
    delayedRequestSeen = true;
    await delayedResponse;
    await route.continue();
  });
  await page.route("**/versions/artifact-spectrum-v2", async (route) => {
    latestRequestSeen = true;
    await route.continue();
  });

  await page.goto("/artifacts/artifact-spectrum");
  const versionOne = page.getByRole("button", { name: "v1 보기" }).filter({ visible: true });
  const versionTwo = page.getByRole("button", { name: "선택됨" }).filter({ visible: true });
  const delayedRequestFinished = page.waitForResponse((response) =>
    response.url().endsWith("/versions/artifact-spectrum-v1"),
  );
  await versionOne.click();
  await expect.poll(() => delayedRequestSeen).toBe(true);

  try {
    await versionTwo.click();
    await expect.poll(() => latestRequestSeen).toBe(true);
    await expect(page.locator('tr[aria-current="true"]')).toContainText("v2");
  } finally {
    releaseDelayedResponse();
  }

  const delayedResponseResult = await delayedRequestFinished;
  await delayedResponseResult.finished();
  await page.waitForTimeout(100);
  await expect(page.locator('tr[aria-current="true"]')).toContainText("v2");
});

test("stale Version failure cannot overwrite the latest success", async ({ page }) => {
  let releaseFailure = (): void => {};
  const delayedFailure = new Promise<void>((resolve) => {
    releaseFailure = resolve;
  });
  let delayedRequestSeen = false;
  await page.route("**/versions/artifact-spectrum-v1", async (route) => {
    delayedRequestSeen = true;
    await delayedFailure;
    await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
  });

  await page.goto("/artifacts/artifact-spectrum");
  await page.getByRole("button", { name: "v1 보기" }).filter({ visible: true }).click();
  await expect.poll(() => delayedRequestSeen).toBe(true);
  const latestResponse = page.waitForResponse((response) =>
    response.url().endsWith("/versions/artifact-spectrum-v2"),
  );
  await page.getByRole("button", { name: "선택됨" }).filter({ visible: true }).click();
  await latestResponse;
  releaseFailure();

  await expect(page.locator('tr[aria-current="true"]')).toContainText("v2");
  await expect(page.locator("#error-region")).toBeHidden();
  await expect(page.locator("#live-region")).toHaveText("선택한 불변 Version을 불러왔습니다.");
});

test("Artifact mutation locks Version selection until the side effect settles", async ({ page }) => {
  let releaseMutation = (): void => {};
  const delayedMutation = new Promise<void>((resolve) => {
    releaseMutation = resolve;
  });
  let mutationSeen = false;
  await page.route("**/attachments", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    mutationSeen = true;
    await delayedMutation;
    await route.continue();
  });

  await page.goto("/artifacts/artifact-spectrum");
  await page.getByRole("button", { name: "세션에 연결" }).click();
  await expect.poll(() => mutationSeen).toBe(true);
  await expect(page.getByRole("button", { name: "v1 보기" }).filter({ visible: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "세션 연결 해제" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "새 Version 생성" })).toBeDisabled();
  releaseMutation();

  await expect(page.getByText("session-demo", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "v1 보기" }).filter({ visible: true })).toBeEnabled();
});

test("failed Artifact actions restore keyboard focus", async ({ page }) => {
  await page.route("**/versions/artifact-spectrum-v1", (route) =>
    route.fulfill({ status: 500, contentType: "application/json", body: "{}" }),
  );
  await page.route("**/attachments", (route) =>
    route.fulfill({ status: 500, contentType: "application/json", body: "{}" }),
  );
  await page.goto("/artifacts/artifact-spectrum");

  const versionOne = page.getByRole("button", { name: "v1 보기" }).filter({ visible: true });
  await versionOne.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#error-region")).toBeVisible();
  await expect(versionOne).toBeFocused();

  const attach = page.getByRole("button", { name: "세션에 연결" });
  await attach.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#live-region")).toHaveText("작업이 완료되지 않았습니다.");
  await expect(attach).toBeFocused();
});

test("unknown Artifact renders a non-disclosing state without actions", async ({ page }) => {
  await page.goto("/artifacts/artifact-foreign");

  await expect(page.getByRole("heading", { name: "페이지를 찾을 수 없습니다" })).toBeVisible();
  await expect(page.getByText("요청한 리소스는 존재하지 않거나 접근할 수 없습니다.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("한국 광물 연구실");
  await expect(page.getByRole("button", { name: "세션에 연결" })).toHaveCount(0);
  await expect(page.locator(".preview-frame")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "검증된 Version 다운로드" })).toHaveCount(0);
});

test("Artifact library server failure stays distinct from not-found", async ({ page }) => {
  await page.route("**/api/v1/artifacts", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: "{}" }),
  );
  await page.goto("/artifacts");

  await expect(page.getByRole("heading", { name: "서버 응답을 확인할 수 없습니다" })).toBeVisible();
  await expect(page.getByText("아티팩트 목록 요청을 처리하지 못했습니다. 잠시 후 재시도하세요.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("한국 광물 연구실");
  await expect(page.getByText("표시할 아티팩트가 없습니다.")).toHaveCount(0);
});

test("Artifact detail network failure has a connection error state", async ({ page }) => {
  await page.route("**/api/v1/artifacts/artifact-spectrum", (route) => route.abort("failed"));
  await page.goto("/artifacts/artifact-spectrum");

  await expect(page.getByRole("heading", { name: "서버에 연결할 수 없습니다" })).toBeVisible();
  await expect(page.getByText("페이지 정보를 불러오지 못했습니다. 네트워크 연결을 확인한 뒤 재시도하세요.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("한국 광물 연구실");
  await expect(page.getByRole("button", { name: "세션에 연결" })).toHaveCount(0);
});

test("authentication failure has an explicit session state", async ({ page }) => {
  await page.route("**/api/v1/me", (route) =>
    route.fulfill({ status: 401, contentType: "application/json", body: "{}" }),
  );
  await page.goto("/artifacts");

  await expect(page.getByRole("heading", { name: "인증 상태를 확인할 수 없습니다" })).toBeVisible();
  await expect(page.getByText("세션을 다시 확인한 뒤 요청을 재시도하세요.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("조직 정보를 표시할 수 없습니다");
  await expect(page.locator(".artifact-library-item")).toHaveCount(0);
});
