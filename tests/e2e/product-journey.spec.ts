import process from "node:process";
import { writeFile } from "node:fs/promises";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { scanAccessibility, scanTouchTargets } from "./accessibility-scan.js";
import { authenticateProduct, productOrigin } from "./product-auth.js";

const productSessionId = "018f0d7d-6b17-7a91-8b31-2f7331677c01";
const captureDirectory = process.env.PRODUCT_UI_CAPTURE_DIR;
const csv = "sample,value,calibration\na,1.0,cal-1\nb,2.5,cal-1\n";

type JourneyIds = Readonly<{
  exportId: string;
  reviewId: string;
  runId: string;
}>;

async function expectVisibleHashes(page: Page): Promise<void> {
  const values = await page.locator("code.hash").allTextContents();
  expect(values.length).toBeGreaterThan(0);
  expect(values.every((value) => /^[a-f0-9]{64}$/u.test(value))).toBe(true);
}

async function fillRunForm(page: Page, suffix: string, fileSuffix: string): Promise<void> {
  await page.locator("#dry-lab-file").setInputFiles({
    name: `calibrated-${fileSuffix}.csv`,
    mimeType: "text/csv",
    buffer: Buffer.from(csv),
  });
  await expect(page.locator("#dry-lab-file-name")).toHaveText(`calibrated-${fileSuffix}.csv`);
  await page.locator("#research-question").fill(`보정 실행 ${suffix}의 재현성을 검증할 수 있는가?`);
  await page.locator("#research-rationale").fill("반복 실행 결과가 입력 순서와 무관한지 확인한다.");
  await page.locator("#research-benefit").fill("검증 가능한 정규화 기준선을 만든다.");
  await page.locator("#research-success-criteria").fill("동일 입력은 동일 체크섬을 만든다.");
  await page.locator("#research-constraints").fill("비임상 연구 데이터만 사용한다.");
  await page.locator("#research-stop-conditions").fill("보정 메타데이터가 없으면 중단한다.");
  await page.locator("#research-mode").selectOption("bounded_agentic");
  await page.locator("#research-data-origin").selectOption("observed");
  await page.locator("#dry-lab-session").selectOption(productSessionId);
  await page.locator("#dry-lab-prompt").fill(`보정값을 정규화하고 ${suffix} 실행 근거를 검토한다.`);
}

async function captureRoute(page: Page, projectName: string, label: string): Promise<void> {
  const viewport = page.viewportSize();
  if (!viewport) throw new Error("Browser viewport is unavailable");
  const assertNoHorizontalOverflow = async (captureLabel: string): Promise<void> => {
    const metrics = await page.evaluate(() => {
      const clientWidth = document.documentElement.clientWidth;
      const overflowing = [...document.querySelectorAll<HTMLElement>("body *")]
        .filter((element) => {
          const box = element.getBoundingClientRect();
          return box.width > 0 && box.height > 0
            && (box.left < -1 || box.right > clientWidth + 1);
        })
        .map((element) => ({
          className: element.className,
          tagName: element.tagName,
          text: (element.textContent ?? "").trim().slice(0, 80),
        }));
      return {
        documentOverflow: document.documentElement.scrollWidth - clientWidth,
        overflowing,
      };
    });
    expect({ captureLabel, ...metrics }).toEqual({
      captureLabel,
      documentOverflow: 0,
      overflowing: [],
    });
    const previewFrame = page.locator('.preview-frame[data-preview-state="loaded"]');
    if (await previewFrame.count()) {
      await expect.poll(async () => {
        const previewMetrics = await page.frameLocator(".preview-frame").locator("img").evaluate((image: HTMLImageElement) => ({
          documentWidth: image.ownerDocument.documentElement.clientWidth,
          imageRight: image.getBoundingClientRect().right,
          renderedWidth: image.getBoundingClientRect().width,
        }));
        return previewMetrics.renderedWidth > 0
          && previewMetrics.imageRight <= previewMetrics.documentWidth + 1;
      }, { message: `${captureLabel} iframe preview must fit its viewport` }).toBe(true);
    }
  };
  await assertNoHorizontalOverflow(`${projectName}-${label}`);
  if (captureDirectory) {
    await settlePaint(page);
    await captureVerifiedPng(page, `${projectName}-${label}.png`, true);
  }
  await page.setViewportSize({ width: Math.ceil(viewport.width / 2), height: viewport.height });
  await assertNoHorizontalOverflow(`${projectName}-${label}-zoom200`);
  if (captureDirectory) {
    await settlePaint(page);
    await captureVerifiedPng(page, `${projectName}-${label}-zoom200.png`, true);
  }
  await page.setViewportSize(viewport);
}

async function settlePaint(page: Page): Promise<void> {
  await page.evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
}

async function writeCapturePng(name: string, screenshot: Buffer): Promise<void> {
  // Boundary checker requires literal destinations for Node write sinks.
  switch (name) {
    case "mobile-375-upload.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-upload.png", screenshot);
      return;
    case "mobile-375-upload-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-upload-zoom200.png", screenshot);
      return;
    case "mobile-375-approval.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-approval.png", screenshot);
      return;
    case "mobile-375-approval-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-approval-zoom200.png", screenshot);
      return;
    case "mobile-375-run.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-run.png", screenshot);
      return;
    case "mobile-375-run-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-run-zoom200.png", screenshot);
      return;
    case "mobile-375-review.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-review.png", screenshot);
      return;
    case "mobile-375-review-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-review-zoom200.png", screenshot);
      return;
    case "mobile-375-export.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-export.png", screenshot);
      return;
    case "mobile-375-export-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-export-zoom200.png", screenshot);
      return;
    case "mobile-375-workspace.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-workspace.png", screenshot);
      return;
    case "mobile-375-workspace-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-workspace-zoom200.png", screenshot);
      return;
    case "mobile-375-artifacts.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-artifacts.png", screenshot);
      return;
    case "mobile-375-artifacts-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-artifacts-zoom200.png", screenshot);
      return;
    case "mobile-375-artifact-detail.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-artifact-detail.png", screenshot);
      return;
    case "mobile-375-artifact-detail-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-artifact-detail-zoom200.png", screenshot);
      return;
    case "mobile-375-providers.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-providers.png", screenshot);
      return;
    case "mobile-375-providers-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-providers-zoom200.png", screenshot);
      return;
    case "tablet-768-upload.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-upload.png", screenshot);
      return;
    case "tablet-768-upload-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-upload-zoom200.png", screenshot);
      return;
    case "tablet-768-approval.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-approval.png", screenshot);
      return;
    case "tablet-768-approval-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-approval-zoom200.png", screenshot);
      return;
    case "tablet-768-run.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-run.png", screenshot);
      return;
    case "tablet-768-run-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-run-zoom200.png", screenshot);
      return;
    case "tablet-768-review.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-review.png", screenshot);
      return;
    case "tablet-768-review-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-review-zoom200.png", screenshot);
      return;
    case "tablet-768-export.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-export.png", screenshot);
      return;
    case "tablet-768-export-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-export-zoom200.png", screenshot);
      return;
    case "tablet-768-workspace.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-workspace.png", screenshot);
      return;
    case "tablet-768-workspace-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-workspace-zoom200.png", screenshot);
      return;
    case "tablet-768-artifacts.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-artifacts.png", screenshot);
      return;
    case "tablet-768-artifacts-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-artifacts-zoom200.png", screenshot);
      return;
    case "tablet-768-artifact-detail.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-artifact-detail.png", screenshot);
      return;
    case "tablet-768-artifact-detail-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-artifact-detail-zoom200.png", screenshot);
      return;
    case "tablet-768-providers.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-providers.png", screenshot);
      return;
    case "tablet-768-providers-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-providers-zoom200.png", screenshot);
      return;
    case "desktop-1280-upload.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-upload.png", screenshot);
      return;
    case "desktop-1280-upload-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-upload-zoom200.png", screenshot);
      return;
    case "desktop-1280-approval.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-approval.png", screenshot);
      return;
    case "desktop-1280-approval-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-approval-zoom200.png", screenshot);
      return;
    case "desktop-1280-run.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-run.png", screenshot);
      return;
    case "desktop-1280-run-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-run-zoom200.png", screenshot);
      return;
    case "desktop-1280-review.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-review.png", screenshot);
      return;
    case "desktop-1280-review-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-review-zoom200.png", screenshot);
      return;
    case "desktop-1280-export.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-export.png", screenshot);
      return;
    case "desktop-1280-export-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-export-zoom200.png", screenshot);
      return;
    case "desktop-1280-workspace.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-workspace.png", screenshot);
      return;
    case "desktop-1280-workspace-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-workspace-zoom200.png", screenshot);
      return;
    case "desktop-1280-artifacts.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-artifacts.png", screenshot);
      return;
    case "desktop-1280-artifacts-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-artifacts-zoom200.png", screenshot);
      return;
    case "desktop-1280-artifact-detail.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-artifact-detail.png", screenshot);
      return;
    case "desktop-1280-artifact-detail-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-artifact-detail-zoom200.png", screenshot);
      return;
    case "desktop-1280-providers.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-providers.png", screenshot);
      return;
    case "desktop-1280-providers-zoom200.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-providers-zoom200.png", screenshot);
      return;
    case "showcase-1280.png":
      await writeFile("artifacts/ulw-g003/current-capture/showcase-1280.png", screenshot);
      return;
    case "showcase-768.png":
      await writeFile("artifacts/ulw-g003/current-capture/showcase-768.png", screenshot);
      return;
    case "showcase-375.png":
      await writeFile("artifacts/ulw-g003/current-capture/showcase-375.png", screenshot);
      return;
    case "desktop-1280-workspace-188.png":
      await writeFile("artifacts/ulw-g003/current-capture/desktop-1280-workspace-188.png", screenshot);
      return;
    case "tablet-768-workspace-188.png":
      await writeFile("artifacts/ulw-g003/current-capture/tablet-768-workspace-188.png", screenshot);
      return;
    case "mobile-375-workspace-188.png":
      await writeFile("artifacts/ulw-g003/current-capture/mobile-375-workspace-188.png", screenshot);
      return;
    default:
      throw new Error(`unsupported capture name: ${name}`);
  }
}

async function captureVerifiedPng(page: Page, captureName: string, fullPage = false): Promise<void> {
  let lastBlackRatio = 1;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const screenshot = await page.screenshot({ fullPage });
    lastBlackRatio = await page.evaluate(async (source) => {
      const image = new Image();
      image.src = source;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const context = canvas.getContext("2d");
      if (!context) return 1;
      context.drawImage(image, 0, 0);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
      let blackPixels = 0;
      for (let offset = 0; offset < pixels.length; offset += 4) {
        if (pixels[offset] <= 1 && pixels[offset + 1] <= 1 && pixels[offset + 2] <= 1 && pixels[offset + 3] >= 254) blackPixels += 1;
      }
      return blackPixels / (pixels.length / 4);
    }, `data:image/png;base64,${screenshot.toString("base64")}`);
    if (lastBlackRatio < 0.005) {
      await writeCapturePng(captureName, screenshot);
      return;
    }
    const viewport = page.viewportSize();
    if (viewport && viewport.height > 1) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height - 1 });
      await page.setViewportSize(viewport);
    }
    await settlePaint(page);
  }
  throw new Error(`Screenshot compositor black ratio remained ${lastBlackRatio.toFixed(4)} for ${captureName}`);
}

async function completeJourney(page: Page, suffix: string, fileSuffix: string, captureProject = ""): Promise<JourneyIds> {
  await page.goto(`${productOrigin}/upload`);
  await expect(page.getByRole("heading", { name: "연구 입력 업로드" })).toBeVisible();
  if (captureProject) await captureRoute(page, captureProject, "upload");
  await fillRunForm(page, suffix, fileSuffix);
  await page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" }).click();
  await expect(page).toHaveURL(new RegExp(`${productOrigin}/runs/[^/]+/approval$`, "u"));
  await expect(page.getByRole("heading", { name: "ActionPlan 승인" })).toBeVisible();
  const runId = new URL(page.url()).pathname.split("/")[2];
  await expect(page.getByText("현재 ActionPlan의 격리 실행 1회")).toBeVisible();
  await expect(page.getByText("승인 유효 기간 승인 후 10분", { exact: true })).toBeVisible();
  await expect(page.locator(".phrase").getByText("승인 만료를 검토합니다.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "계획 거절" })).toBeVisible();
  if (captureProject) await captureRoute(page, captureProject, "approval");

  if (captureProject) {
    await page.evaluate((id) => {
      history.pushState({}, "", `/runs/${id}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, runId);
    await expect(page.getByRole("heading", { name: "연구 실행 기록" })).toBeVisible();
    await expect(page.getByRole("button", { name: "실행 취소" })).toBeVisible();
    await captureRoute(page, captureProject, "run");
    await page.evaluate((id) => {
      history.pushState({}, "", `/runs/${id}/approval`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, runId);
    await expect(page.getByRole("heading", { name: "ActionPlan 승인" })).toBeVisible();
  }

  await page.getByRole("button", { name: "계획 승인" }).click();
  const execute = page.getByRole("button", { name: "승인된 계획 실행" });
  await expect(execute).toBeEnabled();
  expect(await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
    tokenNodes: document.querySelectorAll("[data-token], input[name*=token]").length,
  }))).toEqual({ local: [], session: [], tokenNodes: 0 });

  await execute.click();
  await expect(page).toHaveURL(`${productOrigin}/runs/${runId}`);
  await expect(page.getByRole("region", { name: "현재 상태" }).getByText("격리 실행 완료", { exact: true })).toBeVisible();
  await expect(page.locator(".phrase").getByText("순서대로 추적합니다.", { exact: true })).toBeVisible();
  expect(await page.locator(".run-grid [aria-label]").evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute("aria-label")),
  )).toEqual(["현재 상태", "연결된 아티팩트", "실행 타임라인"]);
  await page.getByRole("button", { name: "검토 결과 생성" }).click();
  await expect(page).toHaveURL(new RegExp(`${productOrigin}/reviews/[^/]+$`, "u"));
  const reviewId = new URL(page.url()).pathname.split("/")[2];
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
  await expect(page.getByText("normalized.csv", { exact: true })).toBeVisible();
  await expect(page.locator(".phrase").getByText("고정된 체크섬을", { exact: true })).toBeVisible();
  await expect(page.locator(".phrase").getByText("확인했습니다.", { exact: true })).toBeVisible();
  expect(await page.locator(".section-grid > .panel").evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute("aria-label")),
  )).toEqual(["검토 발견 사항", "고정된 근거"]);
  if (captureProject) await captureRoute(page, captureProject, "review");

  await page.getByRole("button", { name: "재현성 매니페스트 준비" }).click();
  await expect(page).toHaveURL(new RegExp(`${productOrigin}/exports/[^/]+$`, "u"));
  const exportId = new URL(page.url()).pathname.split("/")[2];
  await expect(page.getByRole("region", { name: "재현성 상태" }).getByText("내보내기 준비 완료", { exact: true })).toBeVisible();
  await expect(page.getByText("artifacts/normalized.csv", { exact: true })).toBeVisible();
  await expectVisibleHashes(page);
  await expect(page.getByText(exportId, { exact: true })).toBeVisible();
  await expect.poll(async () => {
    const box = await page.locator(".cleanup-confirmation").boundingBox();
    return box?.height ?? 0;
  }).toBeGreaterThanOrEqual(44);
  if (captureProject) await captureRoute(page, captureProject, "export");
  return { exportId, reviewId, runId };
}

async function expectForeign404(browser: Browser, path: string): Promise<void> {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await authenticateProduct(page, "foreign");
    const response = await context.request.get(`${productOrigin}${path}`);
    expect(response.status()).toBe(404);
  } finally {
    await context.close();
  }
}

async function routeProviderState(page: Page, withQualifiedConnection = false): Promise<void> {
  await page.route(`${productOrigin}/api/v1/provider-connections/registry`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        adapters: [
          {
            id: "openai_codex",
            name: "OpenAI",
            availability_label: "연결 가능",
            required: true,
            default: true,
            connectable: true,
            disabled_reason: null,
          },
          {
            id: "zai_glm",
            name: "Z.ai GLM",
            availability_label: "GLM 비활성화 · unsupported_auth",
            required: false,
            default: false,
            connectable: false,
            disabled_reason: "unsupported_auth",
          },
        ],
      }),
    }));
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        connections: withQualifiedConnection
          ? [{
              id: "018f0d7d-6b17-7a91-8b31-2f7331677d10",
              adapter_id: "openai_codex",
              account: { id: "account-redacted" },
              models: ["codex-mini"],
              selected_model: "codex-mini",
              status: "healthy",
              health: "healthy",
              qualification: { cleanup_verified: true, live: true },
              revision: "2",
            }]
          : [],
      }),
    }));
}

test.beforeEach(async ({ page }) => {
  await authenticateProduct(page);
});

test("primitive showcase renders under the product CSP", async ({ page }) => {
  const browserErrors: string[] = [];
  await page.emulateMedia({ reducedMotion: "reduce" });
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));

  await page.goto(`${productOrigin}/product/showcase.html`);
  await expect(page.getByRole("heading", { name: /Measured evidence,\s*visible decisions\./u })).toBeVisible();
  const swatchColors = await page.locator(".swatch").evaluateAll((nodes) => nodes.map((node) =>
    getComputedStyle(node, "::before").backgroundColor
  ));
  expect(swatchColors).toHaveLength(5);
  expect(swatchColors.every((color) => color !== "rgba(0, 0, 0, 0)")).toBe(true);
  const reviewButton = page.getByRole("button", { name: "계획 검토" });
  await reviewButton.focus();
  const metrics = await page.evaluate(() => {
    const interactive = [...document.querySelectorAll<HTMLElement>(
      "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])",
    )].filter((node) => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0;
    });
    const focused = document.activeElement instanceof HTMLElement
      ? getComputedStyle(document.activeElement)
      : null;
    return {
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      reducedMotionDuration: getComputedStyle(document.querySelector('[aria-busy="true"]') as HTMLElement).animationDuration,
      shortTargets: interactive.filter((node) => {
        const box = node.getBoundingClientRect();
        return box.width < 44 || box.height < 44;
      }).map((node) => node.textContent?.trim() || node.getAttribute("aria-label")),
      focusOutline: focused ? `${focused.outlineWidth} ${focused.outlineColor}` : "",
    };
  });
  expect(metrics.overflow).toBeLessThanOrEqual(1);
  expect(Number.parseFloat(metrics.reducedMotionDuration)).toBeLessThanOrEqual(0.00001);
  expect(metrics.shortTargets).toEqual([]);
  expect(metrics.focusOutline).toBe("2px rgb(130, 242, 204)");
  expect(browserErrors).toEqual([]);
  if (captureDirectory) {
    const viewport = page.viewportSize();
    if (!viewport) throw new Error("The showcase capture requires a fixed viewport.");
    await settlePaint(page);
    await captureVerifiedPng(page, `showcase-${viewport.width}.png`, true);
  }
});

test("shell keeps labeled 44px navigation and a named primary action at 200 percent", async ({ page }) => {
  await page.goto(`${productOrigin}/workspace`);
  await expect(page.getByRole("heading", { name: "워크스페이스" })).toBeVisible();
  await expect(page.locator(".workspace-action")).toHaveAccessibleName("새 연구 시작");
  await page.setViewportSize({ width: 188, height: 900 });

  const metrics = await page.locator(".global-nav nav").evaluate((nav) => {
    const links = [...nav.querySelectorAll<HTMLElement>("a")];
    const labels = [...nav.querySelectorAll<HTMLElement>(".nav-item-label")];
    return {
      labels: labels.map((label) => ({
        visible: getComputedStyle(label).display !== "none",
        text: label.textContent?.trim() ?? "",
      })),
      shortLinks: links.filter((link) => {
        const box = link.getBoundingClientRect();
        return box.width < 44 || box.height < 44;
      }).map((link) => link.getAttribute("aria-label")),
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
  expect(metrics.labels).toEqual([
    { visible: true, text: "워크스페이스" },
    { visible: true, text: "새 연구" },
    { visible: true, text: "아티팩트" },
    { visible: true, text: "연결" },
  ]);
  expect(metrics.shortLinks).toEqual([]);
  expect(metrics.overflow).toBeLessThanOrEqual(1);
});

test("unknown dynamic resources share the non-disclosing workspace recovery", async ({ page }) => {
  for (const path of [
    "/runs/run-missing",
    "/runs/run-missing/approval",
    "/reviews/review-missing",
    "/exports/export-missing",
  ]) {
    await page.goto(`${productOrigin}${path}`);
    await expect(page.getByRole("heading", { name: "페이지를 찾을 수 없습니다" })).toBeVisible();
    await expect(page.getByText("요청한 리소스는 존재하지 않거나 접근할 수 없습니다.")).toBeVisible();
    const recovery = page.getByRole("link", { name: "워크스페이스로 돌아가기" });
    await expect(recovery).toHaveAttribute("href", "/workspace");
    await expect.poll(async () => (await recovery.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(44);
  }
});

test("browser history route changes focus the new page heading", async ({ page }) => {
  await page.goto(`${productOrigin}/workspace`);
  await expect(page.getByRole("heading", { name: "워크스페이스" })).toBeVisible();
  await page.evaluate(() => {
    history.pushState({}, "", "/artifacts");
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
  const artifactsHeading = page.getByRole("heading", { name: "아티팩트 라이브러리" });
  await expect(artifactsHeading).toBeVisible();
  await expect(artifactsHeading).toBeFocused();
});

test("failed Run creation reports an alert and restores focus", async ({ page }) => {
  await page.goto(`${productOrigin}/upload`);
  await expect(page.locator("#research-mode")).toHaveValue("");
  await expect(page.locator("#research-data-origin")).toHaveValue("");
  const create = page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" });
  await create.click();
  await expect(page.getByRole("alert")).toContainText("업로드할 연구 입력 파일을 선택하세요.");
  await expect(create).toBeFocused();
  await expect(create).toBeEnabled();
});

test("provider Run creation sends the complete intent before approval", async ({ page }) => {
  await routeProviderState(page, true);
  let submitted: unknown = null;
  await page.route(`${productOrigin}/api/v1/runs`, async (route) => {
    submitted = route.request().postDataJSON();
    await route.fulfill({
      status: 400,
      contentType: "application/json",
      body: '{"error":"intent-contract-observed"}',
    });
  });
  await page.goto(`${productOrigin}/upload`);
  await fillRunForm(page, "제공자 승인 경계", "provider-intent");
  await page.locator("#run-execution-target").selectOption(
    "018f0d7d-6b17-7a91-8b31-2f7331677d10",
  );
  await page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" }).click();

  await expect.poll(() => submitted).toMatchObject({
    execution_mode: "provider_model",
    connection_id: "018f0d7d-6b17-7a91-8b31-2f7331677d10",
    model_id: "codex-mini",
    prompt: expect.any(String),
    research_intent: {
      question: expect.any(String),
      rationale: expect.any(String),
      intended_benefit: expect.any(String),
      success_criteria: expect.any(Array),
      constraints: expect.any(Array),
      stop_conditions: expect.any(Array),
    },
    input: {
      filename: "calibrated-provider-intent.csv",
      media_type: "text/csv",
      content: expect.any(String),
    },
  });
});

test("malformed exact resource response fails closed", async ({ page }) => {
  await authenticateProduct(page, "foreign");
  await page.goto(`${productOrigin}/upload`);
  await fillRunForm(page, "계약 오류", "contract-error");
  await page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" }).click();
  const runId = new URL(page.url()).pathname.split("/")[2];
  await page.route(`${productOrigin}/api/v1/runs/${runId}`, async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: '{"stage":"execute"}' });
  });

  await page.goto(`${productOrigin}/runs/${runId}`);
  await expect(page.getByRole("alert")).toContainText("서버의 실행 리소스 응답을 확인할 수 없습니다.");
  await expect(page.getByRole("heading", { name: "서버 응답을 확인할 수 없습니다" })).toBeVisible();
  await expect(page.getByRole("button", { name: "승인된 계획 실행" })).toHaveCount(0);
});

test("two exact Runs complete plan through export and remain session isolated", async ({ page, browser }, testInfo) => {
  await page.goto(`${productOrigin}/workspace`);
  await expect(page.getByRole("heading", { name: "워크스페이스" })).toBeVisible();
  await captureRoute(page, testInfo.project.name, "workspace");
  const first = await completeJourney(page, "첫 번째", "first", testInfo.project.name);
  await page.goBack();
  await expect(page.getByRole("heading", { name: "검토 결과" })).toBeVisible();
  await expect(page).toHaveURL(`${productOrigin}/reviews/${first.reviewId}`);
  await page.goForward();
  await expect(page.getByRole("heading", { name: "내보내기" })).toBeVisible();
  await expect(page).toHaveURL(`${productOrigin}/exports/${first.exportId}`);

  await page.goto(`${productOrigin}/artifacts`);
  await expect(page.getByRole("heading", { name: "아티팩트 라이브러리", exact: true })).toBeVisible();
  await captureRoute(page, testInfo.project.name, "artifacts");
  const artifactHref = await page.getByRole("link", { name: "preview.png", exact: true }).last().getAttribute("href");
  expect(artifactHref).toMatch(/^\/artifacts\/[0-9a-f-]+$/u);
  await page.goto(`${productOrigin}${artifactHref}`);
  await expect(page.getByRole("heading", { name: "아티팩트", exact: true })).toBeVisible();
  const artifactId = artifactHref?.split("/").at(-1);
  const versionDetail = page.getByRole("region", { name: "선택 Version 상세" });
  await expect(versionDetail.getByText("불변", { exact: true })).toBeVisible();
  await expect(versionDetail.getByText(artifactId ?? "", { exact: true })).toBeVisible();
  await expect(
    versionDetail.locator(".key-values dd").filter({ hasText: /^2026-07-15T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u }),
  ).toHaveCount(1);
  await expect(page.locator(".preview-frame")).toHaveAttribute("data-preview-state", "loaded");
  await expect(page.locator(".preview-frame")).toHaveAttribute("sandbox", "allow-same-origin");
  const previewImage = page.frameLocator(".preview-frame").locator("img");
  await expect(previewImage).toBeVisible();
  expect(await previewImage.evaluate((image: HTMLImageElement) => ({
    height: image.naturalHeight,
    width: image.naturalWidth,
  }))).toEqual({ height: 180, width: 320 });
  const renderedColorCount = await previewImage.evaluate((image: HTMLImageElement) => {
    const canvas = image.ownerDocument.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d");
    if (!context) return 0;
    context.drawImage(image, 0, 0);
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
    const colors = new Set<string>();
    for (let offset = 0; offset < pixels.length; offset += 4) {
      colors.add(`${pixels[offset]}:${pixels[offset + 1]}:${pixels[offset + 2]}:${pixels[offset + 3]}`);
      if (colors.size > 4) break;
    }
    return colors.size;
  });
  expect(renderedColorCount).toBeGreaterThan(4);
  expect(await page.locator(".artifact-layout > *").evaluateAll((nodes) =>
    nodes.map((node) => node.classList.contains("stack") ? "detail" : node.getAttribute("aria-label")),
  )).toEqual(["detail", "아티팩트 버전"]);
  await captureRoute(page, testInfo.project.name, "artifact-detail");

  await routeProviderState(page);
  await page.goto(`${productOrigin}/settings/providers`);
  await expect(page.getByRole("heading", { name: "제공자 설정" })).toBeVisible();
  await expect(page.getByText("GLM 비활성화 · unsupported_auth", { exact: true })).toBeVisible();
  await expect(page.locator('[data-adapter-id="zai_glm"]')).toContainText("비활성 이유: unsupported_auth");
  await expect(page.locator('[data-adapter-id="zai_glm"] button')).toHaveCount(0);
  await captureRoute(page, testInfo.project.name, "providers");
  const firstRun = await page.request.get(`${productOrigin}/api/v1/runs/${first.runId}`);
  expect(firstRun.status()).toBe(200);
  const firstBody = await firstRun.json() as Record<string, unknown>;

  const second = await completeJourney(page, "두 번째", "second");
  expect(second.runId).not.toBe(first.runId);
  expect(second.reviewId).not.toBe(first.reviewId);
  expect(second.exportId).not.toBe(first.exportId);
  const secondRun = await page.request.get(`${productOrigin}/api/v1/runs/${second.runId}`);
  const secondBody = await secondRun.json() as Record<string, unknown>;
  expect(secondBody.research_intent_sha256).not.toBe(firstBody.research_intent_sha256);
  expect(secondBody.plan_digest).not.toBe(firstBody.plan_digest);

  for (const [kind, id] of [
    ["runs", first.runId],
    ["reviews", first.reviewId],
    ["exports", first.exportId],
  ] as const) {
    const exactPath = `/api/v1/${kind}/${id}`;
    expect((await page.request.get(`${productOrigin}${exactPath}`)).status()).toBe(200);
    expect((await page.request.get(`${productOrigin}/api/v1/${kind}/unknown-${id}`)).status()).toBe(404);
    await expectForeign404(browser, exactPath);
  }

  await page.goto(`${productOrigin}/runs/${first.runId}`);
  await page.reload();
  await expect(page.getByRole("heading", { name: "연구 실행 기록" })).toBeVisible();
  await expect(page.getByRole("region", { name: "현재 상태" }).getByText("내보내기 준비 완료", { exact: true })).toBeVisible();
  await page.goto(`${productOrigin}/reviews/${first.reviewId}`);
  await page.reload();
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
  await page.goto(`${productOrigin}/exports/${first.exportId}`);
  await page.reload();
  await expectVisibleHashes(page);
});

test("product journey controls and CJK content reflow through 188px", async ({ page, browser }, testInfo) => {
  await page.goto(`${productOrigin}/workspace`);
  await expect(page.getByRole("heading", { name: "워크스페이스" })).toBeVisible();
  const recentStatusLabels = await page.getByRole("region", { name: "최근 활동" })
    .locator(".activity-status").allTextContents();
  const activityItems = page.getByRole("region", { name: "최근 활동" }).locator(".activity-list > li");
  const expectedRunCount = await activityItems.count();
  expect(expectedRunCount).toBeGreaterThanOrEqual(1);
  const visibleRunIds = await activityItems.locator(".activity-run-id").allTextContents();
  const visibleCreationTimes = await activityItems.locator("time").allTextContents();
  await expect(activityItems).toHaveCount(expectedRunCount);
  expect(visibleRunIds).toHaveLength(expectedRunCount);
  expect(new Set(visibleRunIds).size).toBe(expectedRunCount);
  expect(visibleRunIds.every((id) => /^Run [0-9a-f]{8}$/u.test(id))).toBe(true);
  expect(visibleCreationTimes).toHaveLength(expectedRunCount);
  expect(visibleCreationTimes.every((timestamp) => /^2026-07-15T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(timestamp))).toBe(true);
  expect(recentStatusLabels).toHaveLength(expectedRunCount);
  expect(recentStatusLabels.every((label) => [
    "계획 승인 대기",
    "계획 승인 완료",
    "계획 승인 거절",
    "실행 취소 완료",
    "계획 승인 만료",
    "격리 실행 완료",
    "근거 검토 완료",
    "내보내기 준비 완료",
    "런타임 정리 완료",
  ].includes(label))).toBe(true);
  await expect(activityItems.locator(".activity-links")).toHaveCount(expectedRunCount);
  expect(await scanAccessibility(page)).toEqual([]);
  expect(await scanTouchTargets(page)).toEqual([]);

  for (const width of [1280, 768, 375, 188]) {
    await page.setViewportSize({ width, height: 900 });
    const metrics = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      shortTargets: [...document.querySelectorAll<HTMLElement>(".activity-links a, .resource-link")]
        .filter((node) => {
          const box = node.getBoundingClientRect();
          return box.width > 0 && box.height > 0 && box.height < 44;
        }).map((node) => node.textContent),
    }));
    expect(metrics.scrollWidth - metrics.clientWidth).toBeLessThanOrEqual(1);
    expect(metrics.shortTargets).toEqual([]);
  }
  if (captureDirectory) {
    const captureContext = await browser.newContext({
      storageState: await page.context().storageState(),
      viewport: { width: 188, height: 900 },
    });
    const capturePage = await captureContext.newPage();
    try {
      await capturePage.goto(`${productOrigin}/workspace`);
      await expect(capturePage.getByRole("heading", { name: "워크스페이스" })).toBeVisible();
      const documentHeight = await capturePage.evaluate(() => document.documentElement.scrollHeight);
      await capturePage.setViewportSize({ width: 188, height: documentHeight });
      await settlePaint(capturePage);
      await captureVerifiedPng(capturePage, `${testInfo.project.name}-workspace-188.png`);
    } finally {
      await captureContext.close();
    }
  }
});

test("rejected Review remains a danger finding without success copy", async ({ page }) => {
  await authenticateProduct(page, "foreign");
  const journey = await completeJourney(page, "거부 판정", "rejected");
  const endpoint = `${productOrigin}/api/v1/reviews/${journey.reviewId}`;
  await page.route(endpoint, async (route) => {
    const response = await route.fetch();
    const resource = await response.json() as Record<string, unknown>;
    const review = resource.review as Record<string, unknown>;
    await route.fulfill({
      response,
      contentType: "application/json",
      body: JSON.stringify({ ...resource, review: { ...review, verdict: "rejected" } }),
    });
  });

  await page.goto(`${productOrigin}/reviews/${journey.reviewId}`);
  await expect(page.locator(".status.danger")).toHaveText("rejected");
  await expect(page.getByText("독립 검토에서 실행 결과 또는 고정된 체크섬의 불일치를 발견했습니다.")).toBeVisible();
  await expect(page.getByText("독립 검토가 실행 결과와 고정된 체크섬을 확인했습니다.")).toHaveCount(0);
});

test("approval rejection and Run cancellation are terminal and output-free", async ({ page }) => {
  await authenticateProduct(page, "foreign");
  await page.goto(`${productOrigin}/upload`);
  await fillRunForm(page, "승인 거절", "approval-reject");
  await page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" }).click();
  await expect(page).toHaveURL(new RegExp(`${productOrigin}/runs/[^/]+/approval$`, "u"));
  const rejectedRunId = new URL(page.url()).pathname.split("/")[2];
  await page.getByRole("button", { name: "계획 거절" }).click();

  await expect(page).toHaveURL(`${productOrigin}/runs/${rejectedRunId}`);
  await expect(page.getByRole("region", { name: "현재 상태" }).locator(".status.danger")).toHaveText("계획 승인 거절");
  await expect(page.getByRole("button", { name: "승인된 계획 실행" })).toHaveCount(0);
  const rejectedResource = await (await page.request.get(`${productOrigin}/api/v1/runs/${rejectedRunId}`)).json() as Record<string, unknown>;
  expect(rejectedResource).toMatchObject({ artifacts: [], export_id: null, review_id: null, stage: "reject" });

  await page.goto(`${productOrigin}/upload`);
  await fillRunForm(page, "실행 취소", "run-cancel");
  await page.getByRole("button", { name: "Run 생성 및 ActionPlan 고정" }).click();
  await expect(page).toHaveURL(new RegExp(`${productOrigin}/runs/[^/]+/approval$`, "u"));
  const cancelledRunId = new URL(page.url()).pathname.split("/")[2];
  await page.getByRole("button", { name: "계획 승인" }).click();
  await expect(page.getByText(/^승인 만료 시각 /u)).toBeVisible();
  await page.getByRole("button", { name: "실행 취소" }).click();

  await expect(page).toHaveURL(`${productOrigin}/runs/${cancelledRunId}`);
  await expect(page.getByRole("region", { name: "현재 상태" }).locator(".status.danger")).toHaveText("실행 취소 완료");
  await expect(page.getByRole("button", { name: "검토 결과 생성" })).toHaveCount(0);
  const cancelledResource = await (await page.request.get(`${productOrigin}/api/v1/runs/${cancelledRunId}`)).json() as Record<string, unknown>;
  expect(cancelledResource).toMatchObject({ artifacts: [], export_id: null, review_id: null, stage: "cancel" });
});

test("provider authorization links require the independent client allowlist", async ({ page }) => {
  let authorizationUrl = "https://provider.example.test.attacker.test/authorize";
  await routeProviderState(page);
  await page.route(`${productOrigin}/api/v1/provider-connections`, (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ connections: [] }) });
    }
    return route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        authorization_url: authorizationUrl,
        device_instruction: null,
        expires_at: new Date(Date.now() + 600_000).toISOString(),
        flow: "callback",
        revision: "0",
        state: "state-safe",
      }),
    });
  });
  await page.goto(`${productOrigin}/settings/providers`);
  await page.getByRole("button", { name: "OpenAI 연결" }).click();
  await expect(page.locator("#provider-authorization-link")).toHaveCount(0);
  await expect(page.getByText("안전한 제공자 인증 경로를 확인할 수 없어 링크를 표시하지 않았습니다.")).toBeVisible();

  authorizationUrl = "https://provider.example.test/authorize?state=state-safe";
  await page.reload();
  await page.getByRole("button", { name: "OpenAI 연결" }).click();
  await expect(page.locator("#provider-authorization-link")).toHaveAttribute("href", authorizationUrl);
});

test("product document sends the strict CSP", async ({ page }) => {
  const response = await page.goto(`${productOrigin}/workspace`);
  expect(response?.headers()["content-security-policy"]).toBe(
    "default-src 'none'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; frame-src 'self' blob:; img-src 'self' blob: data:; object-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'",
  );
});

test("malformed cleanup response fails closed", async ({ page }) => {
  await authenticateProduct(page, "foreign");
  await completeJourney(page, "정리 계약 오류", "cleanup-contract");
  await page.route(`${productOrigin}/api/v1/runs/*/cleanup`, async (route) => {
    const response = await route.fetch({
      headers: {
        ...route.request().headers(),
        host: new URL(productOrigin).host,
        origin: productOrigin,
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
      },
    });
    const rawResource = await response.text();
    expect(response.status(), rawResource).toBe(200);
    const resource = JSON.parse(rawResource) as Record<string, unknown>;
    await route.fulfill({
      response,
      contentType: "application/json",
      body: JSON.stringify({ ...resource, cleanup: { removed_runtime_data: true } }),
    });
  });

  const cleanup = page.getByRole("button", { name: "런타임 데이터 정리" });
  await cleanup.click();
  await expect(page.getByRole("alert")).toContainText("제거 대상과 보존 대상을 확인한 뒤 정리에 동의하세요.");
  await expect(page.locator("#cleanup-confirmation")).toBeFocused();
  await page.locator("#cleanup-confirmation").check();
  await cleanup.click();
  await expect(page.getByRole("alert")).toContainText("서버의 실행 리소스 응답을 확인할 수 없습니다.");
  await expect(page.getByRole("button", { name: "런타임 데이터 정리" })).toBeFocused();
});
