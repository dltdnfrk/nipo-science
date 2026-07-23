import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import process from "node:process";
import { expect, test, type Locator, type Page } from "@playwright/test";

const visualCaptureDirectory = process.env.VISUAL_CAPTURE_DIR;

async function tabTo(page: Page, target: Locator): Promise<void> {
  for (let step = 0; step < 64; step += 1) {
    if (await target.evaluate((node) => node === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error("Target was not reachable with keyboard Tab navigation");
}

async function routeProviderShell(page: Page): Promise<void> {
  await page.route("**/settings/providers", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      path: resolve("apps/web/product/index.html"),
    }),
  );
}

async function routeProviderState(page: Page): Promise<void> {
  await page.route("**/api/v1/provider-connections/registry", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        adapters: [{
          id: "openai_codex",
          name: "OpenAI",
          availability_label: "연결 가능",
          required: true,
          default: true,
          connectable: true,
          disabled_reason: null,
        }],
      }),
    }),
  );
  await page.route("**/api/v1/provider-connections", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        connections: [{
          id: "connection-openai",
          adapter_id: "openai_codex",
          account: { id: "researcher@example.invalid" },
          models: ["gpt-research"],
          selected_model: "gpt-research",
          status: "pending",
          health: "pending",
          qualification: { cleanup_verified: false, live: false },
          revision: "revision-1",
        }],
      }),
    }),
  );
}

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
  const versionDetail = page.getByRole("region", { name: "선택 Version 상세" });
  await expect(versionDetail.getByText("불변", { exact: true })).toBeVisible();
  const selectedVersion = page.locator(
    'tr[aria-current="true"] [data-action="select-version"]',
  );
  const selectedVersionId = await selectedVersion.getAttribute("data-version-id");
  expect(selectedVersionId).toMatch(/^artifact-spectrum-v\d+$/u);
  await expect(versionDetail.getByText(selectedVersionId ?? "", { exact: true })).toBeVisible();
  await expect(
    versionDetail.locator(".key-values dd").filter({ hasText: /^\d{4}-\d{2}-\d{2}T/u }),
  ).toHaveCount(1);

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
  await expect(page.locator(".key-values dd").filter({ hasText: /^session-demo$/ })).toBeVisible();

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
    "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1",
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
  const current = await page.request.get("/api/v1/artifacts/artifact-spectrum");
  expect(current.ok()).toBe(true);
  const currentBody = await current.json();
  const latestVersionId = String(currentBody.selected.id);
  const latestVersionLabel = `v${currentBody.selected.version_no}`;
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
  await page.route(`**/versions/${latestVersionId}`, async (route) => {
    latestRequestSeen = true;
    await route.continue();
  });

  await page.goto("/artifacts/artifact-spectrum");
  const versionOne = page.getByRole("button", { name: "v1 보기" }).filter({ visible: true });
  const latestVersion = page.getByRole("button", { name: "선택됨" }).filter({ visible: true });
  const delayedRequestFinished = page.waitForResponse((response) =>
    response.url().endsWith("/versions/artifact-spectrum-v1"),
  );
  await versionOne.click();
  await expect.poll(() => delayedRequestSeen).toBe(true);

  try {
    await latestVersion.click();
    await expect.poll(() => latestRequestSeen).toBe(true);
    await expect(page.locator('tr[aria-current="true"]')).toContainText(latestVersionLabel);
  } finally {
    releaseDelayedResponse();
  }

  const delayedResponseResult = await delayedRequestFinished;
  await delayedResponseResult.finished();
  await expect(page.locator('tr[aria-current="true"]')).toContainText(latestVersionLabel);
});

test("stale Version failure cannot overwrite the latest success", async ({ page }) => {
  const current = await page.request.get("/api/v1/artifacts/artifact-spectrum");
  expect(current.ok()).toBe(true);
  const currentBody = await current.json();
  const latestVersionId = String(currentBody.selected.id);
  const latestVersionLabel = `v${currentBody.selected.version_no}`;
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
    response.url().endsWith(`/versions/${latestVersionId}`),
  );
  await page.getByRole("button", { name: "선택됨" }).filter({ visible: true }).click();
  await latestResponse;
  releaseFailure();

  await expect(page.locator('tr[aria-current="true"]')).toContainText(latestVersionLabel);
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

  await expect(page.locator(".key-values dd").filter({ hasText: /^session-demo$/ })).toBeVisible();
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

test("unknown Artifact renders a non-disclosing state without actions", async ({ page }, testInfo) => {
  await page.goto("/artifacts/artifact-foreign");

  await expect(page.getByRole("heading", { name: "페이지를 찾을 수 없습니다" })).toBeVisible();
  await expect(page.getByText("요청한 리소스는 존재하지 않거나 접근할 수 없습니다.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("Nipo Labs");
  await expect(page.getByRole("button", { name: "세션에 연결" })).toHaveCount(0);
  await expect(page.locator(".preview-frame")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "검증된 Version 다운로드" })).toHaveCount(0);
  if (visualCaptureDirectory) {
    await page.screenshot({
      path: join(visualCaptureDirectory, `unknown-artifact-${testInfo.project.name}.png`),
      fullPage: true,
    });
  }
});

test("Artifact library server failure stays distinct from not-found", async ({ page }, testInfo) => {
  await page.route("**/api/v1/artifacts", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: "{}" }),
  );
  await page.goto("/artifacts");

  await expect(page.getByRole("heading", { name: "서버 응답을 확인할 수 없습니다" })).toBeVisible();
  await expect(page.getByText("아티팩트 목록 요청을 처리하지 못했습니다. 잠시 후 재시도하세요.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("Nipo Labs");
  await expect(page.getByText("표시할 아티팩트가 없습니다.")).toHaveCount(0);
  if (visualCaptureDirectory) {
    await page.screenshot({
      path: join(visualCaptureDirectory, `artifact-server-error-${testInfo.project.name}.png`),
      fullPage: true,
    });
  }
});

test("Artifact detail network failure has a connection error state", async ({ page }) => {
  await page.route("**/api/v1/artifacts/artifact-spectrum", (route) => route.abort("failed"));
  await page.goto("/artifacts/artifact-spectrum");

  await expect(page.getByRole("heading", { name: "서버에 연결할 수 없습니다" })).toBeVisible();
  await expect(page.getByText("페이지 정보를 불러오지 못했습니다. 네트워크 연결을 확인한 뒤 재시도하세요.")).toBeVisible();
  await expect(page.locator("#organization-name")).toHaveText("Nipo Labs");
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

test("provider HTTP failure is not presented as a network outage", async ({ page }) => {
  await routeProviderShell(page);
  await page.goto("/settings/providers");

  await expect(page.getByRole("heading", { name: "정보를 표시할 수 없습니다" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "서버에 연결할 수 없습니다" })).toHaveCount(0);
  await expect(page.locator("#organization-name")).toHaveText("Nipo Labs");
});

test("malformed provider success is reported as an upstream response failure", async ({ page }) => {
  await routeProviderShell(page);
  await page.route("**/api/v1/provider-connections/registry", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        adapters: [{
          id: "openai_codex",
          default: true,
          connectable: true,
          disabled_reason: null,
        }],
      }),
    }),
  );
  await page.route("**/api/v1/provider-connections", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ connections: [] }),
    }),
  );
  await page.goto("/settings/providers");

  await expect(page.getByRole("heading", { name: "서버 응답을 확인할 수 없습니다" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "서버에 연결할 수 없습니다" })).toHaveCount(0);
});

test("provider enums render as Korean status and failed actions restore focus", async ({ page }) => {
  await routeProviderShell(page);
  await routeProviderState(page);
  await page.route("**/api/v1/provider-connections/connection-openai/health", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: { message: "상태 확인 권한이 없습니다." } }),
    }),
  );
  await page.goto("/settings/providers");

  await expect(page.getByText("연결 대기", { exact: true })).toHaveCount(3);
  await expect(page.getByText("pending", { exact: true })).toHaveCount(0);
  const health = page.getByRole("button", { name: "상태 확인" });
  await health.focus();
  await page.keyboard.press("Enter");
  await expect(page.locator("#error-region")).toHaveText("상태 확인 권한이 없습니다.");
  await expect(health).toBeFocused();
});

test("provider cleanup receipt uses the server-owned display name", async ({ page }) => {
  await routeProviderShell(page);
  await routeProviderState(page);
  await page.route("**/api/v1/provider-connections/connection-openai", (route) => {
    if (route.request().method() !== "DELETE") return route.fallback();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        cleanup_receipt: {
          connection_id: "connection-openai",
          adapter_id: "openai_codex",
          evidence_sha256: "a".repeat(64),
          destroyed_at: "2026-07-15T03:30:00Z",
        },
      }),
    });
  });
  await page.goto("/settings/providers");

  await page.getByRole("button", { name: "연결 해제" }).click();
  const receipt = page.getByRole("heading", { name: "민감정보가 제외된 정리 영수증" }).locator("..");
  await expect(receipt).toContainText("OpenAI");
  await expect(receipt).not.toContainText("openai_codex");
  await expect(page.locator("#error-region")).toBeHidden();
});

test("provider navigation keeps the current destination visible at supported widths", async ({ page }) => {
  await routeProviderShell(page);
  await routeProviderState(page);

  for (const width of [375, 768, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/settings/providers");
    const current = page.getByRole("link", { name: "연결" });
    await expect(current).toHaveAttribute("aria-current", "page");
    const box = await current.boundingBox();
    expect(box).not.toBeNull();
    if (!box) throw new Error("Current provider navigation link has no layout box");
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(width);
    const links = page.getByRole("navigation", { name: "제품 메뉴" }).getByRole("link");
    await expect(links).toHaveCount(4);
    for (let index = 0; index < 4; index += 1) {
      const linkBox = await links.nth(index).boundingBox();
      expect(linkBox).not.toBeNull();
      if (!linkBox) throw new Error("Provider navigation link has no layout box");
      expect(linkBox.x).toBeGreaterThanOrEqual(0);
      expect(linkBox.x + linkBox.width).toBeLessThanOrEqual(width);
    }
    expect(await page.evaluate(() => document.body.scrollWidth)).toBe(width);
  }
});

test("188px preserves connected CJK phrase units without overflow", async ({ page }, testInfo) => {
  await routeProviderShell(page);
  await routeProviderState(page);
  await page.setViewportSize({ width: 188, height: 900 });
  await page.goto("/settings/providers");
  await expect(page.getByRole("region", { name: "연결 정책" })).toContainText(
    "자동 대체 없음",
  );

  for (const phrase of ["OAuth 구독", "자동 대체", "없음"]) {
    const phraseNode = page.locator(".phrase").filter({ hasText: new RegExp(`^${phrase}$`, "u") });
    await expect(phraseNode).toHaveCount(1);
    const metrics = await phraseNode.evaluate((node) => ({
      clientWidth: document.documentElement.clientWidth,
      phraseLeft: node.getBoundingClientRect().left,
      phraseRight: node.getBoundingClientRect().right,
      rectCount: node.getClientRects().length,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(metrics.scrollWidth).toBe(metrics.clientWidth);
    expect(metrics.rectCount).toBe(1);
    expect(metrics.phraseLeft).toBeGreaterThanOrEqual(0);
    expect(metrics.phraseRight).toBeLessThanOrEqual(metrics.clientWidth);
  }
  if (visualCaptureDirectory) {
    await page.screenshot({
      path: join(visualCaptureDirectory, `${testInfo.project.name}-provider-188.png`),
      fullPage: true,
    });
  }

  await page.goto("/artifacts/artifact-image");
  // The guidance sentence now splits into two phrase units so it reflows on
  // canvases where a platform font renders the combined unit wider than the
  // 188px line (the unit-integrity assertions below are unchanged).
  const guidance = page.locator(".phrase", { hasText: "다운로드해" });
  await expect(guidance).toHaveCount(1);
  const guidanceMetrics = await guidance.evaluate((node) => ({
    clientWidth: document.documentElement.clientWidth,
    phraseLeft: node.getBoundingClientRect().left,
    phraseRight: node.getBoundingClientRect().right,
    rectCount: node.getClientRects().length,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(guidanceMetrics.scrollWidth).toBe(guidanceMetrics.clientWidth);
  expect(guidanceMetrics.rectCount).toBe(1);
  expect(guidanceMetrics.phraseLeft).toBeGreaterThanOrEqual(0);
  expect(guidanceMetrics.phraseRight).toBeLessThanOrEqual(guidanceMetrics.clientWidth);
  if (visualCaptureDirectory) {
    await page.screenshot({
      path: join(visualCaptureDirectory, `${testInfo.project.name}-artifacts-detail-188.png`),
      fullPage: true,
    });
  }
});
