import { expect, test, type ConsoleMessage, type Locator, type Page } from "@playwright/test";
import { scanAccessibility, scanTouchTargets } from "./accessibility-scan.js";

async function tabTo(page: Page, target: Locator): Promise<void> {
  for (let step = 0; step < 24; step += 1) {
    if (await target.evaluate((node) => node === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error("Target was not reachable with keyboard Tab navigation");
}

function captureProductErrors(page: Page, productOrigin: string): string[] {
  const errors: string[] = [];
  page.on("console", (message: ConsoleMessage) => {
    const source = message.location().url;
    if (message.type() === "error" && (!source || source.startsWith(productOrigin))) {
      errors.push(`console: ${message.text()}`);
    }
  });
  page.on("pageerror", (error: Error) => errors.push(`pageerror: ${error.message}`));
  return errors;
}

test("WCAG 2.2 AA semantics, current navigation, and keyboard flow", async ({ page, baseURL }) => {
  if (!baseURL) throw new Error("The accessibility project requires a configured baseURL.");
  const browserErrors = captureProductErrors(page, new URL(baseURL).origin);
  await page.goto("/artifacts");
  await expect(page.getByRole("heading", { name: "아티팩트 라이브러리" })).toBeVisible();
  await expect(page.locator("#screen")).toHaveAttribute("aria-busy", "false");
  await expect(page.getByRole("link", { name: "아티팩트", exact: true })).toHaveAttribute(
    "aria-current",
    "page",
  );

  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "본문으로 건너뛰기" });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  await page.reload();
  const currentLink = page.getByRole("link", { name: "아티팩트", exact: true });
  await tabTo(page, currentLink);
  await expect(currentLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/artifacts$/u);

  const libraryViolations = await scanAccessibility(page);
  await page.goto("/artifacts/artifact-image");
  await expect(page.getByRole("heading", { name: "아티팩트", exact: true })).toBeVisible();
  const detailViolations = await scanAccessibility(page);
  expect({ detailViolations, libraryViolations }).toEqual({
    detailViolations: [],
    libraryViolations: [],
  });
  expect(browserErrors).toEqual([]);
});

test("44px targets, CJK and hashes reflow without horizontal overflow at 200%", async ({ page, baseURL }) => {
  if (!baseURL) throw new Error("The accessibility project requires a configured baseURL.");
  const browserErrors = captureProductErrors(page, new URL(baseURL).origin);
  await page.goto("/artifacts");
  await expect(page.getByRole("heading", { name: "아티팩트 라이브러리" })).toBeVisible();

  const libraryTouchTargets = await scanTouchTargets(page);
  const normalMetrics = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(normalMetrics.scrollWidth).toBeLessThanOrEqual(normalMetrics.clientWidth + 1);

  await page.goto("/artifacts/artifact-image");
  await expect(page.getByRole("heading", { name: "아티팩트", exact: true })).toBeVisible();
  const detailTouchTargets = await scanTouchTargets(page);
  const detailNormalMetrics = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));

  const viewport = page.viewportSize();
  if (!viewport) throw new Error("The accessibility project requires a fixed viewport.");
  await page.setViewportSize({
    width: Math.ceil(viewport.width / 2),
    height: Math.ceil(viewport.height / 2),
  });
  const detailZoomMetrics = await page.evaluate(() => {
    const wrapped = [...document.querySelectorAll<HTMLElement>(".hash, .key-values dd, p, h1, h2, h3")]
      .filter((element) => getComputedStyle(element).display !== "none")
      .map((element) => ({
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
        text: (element.textContent ?? "").slice(0, 80),
      }))
      .filter((item) => item.scrollWidth > item.clientWidth + 1);
    const koreanControlWordBreak = [
      ...document.querySelectorAll<HTMLElement>("button, .download-link"),
    ]
      .filter((element) => {
        const box = element.getBoundingClientRect();
        return box.width > 0 && box.height > 0 && /[\uac00-\ud7a3]/u.test(element.textContent ?? "");
      })
      .map((element) => ({
        text: (element.textContent ?? "").trim(),
        wordBreak: getComputedStyle(element).wordBreak,
      }))
      .filter((item) => item.wordBreak !== "keep-all");
    return {
      clientWidth: document.documentElement.clientWidth,
      koreanControlWordBreak,
      scrollWidth: document.documentElement.scrollWidth,
      wrapped,
    };
  });
  await page.goto("/artifacts");
  await expect(page.getByRole("heading", { name: "아티팩트 라이브러리" })).toBeVisible();
  const libraryZoomMetrics = await page.evaluate(() => {
    const internalOverflow = [...document.querySelectorAll<HTMLElement>(
      ".artifact-library-item, .artifact-library-item h3 a",
    )]
      .map((element) => ({
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
        text: (element.textContent ?? "").trim().slice(0, 80),
      }))
      .filter((item) => item.scrollWidth > item.clientWidth + 1);
    return {
      clientWidth: document.documentElement.clientWidth,
      internalOverflow,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });

  expect({
    detailNormalOverflow: detailNormalMetrics.scrollWidth - detailNormalMetrics.clientWidth,
    detailTouchTargets,
    detailKoreanControlWordBreak: detailZoomMetrics.koreanControlWordBreak,
    detailWrappedAt200Percent: detailZoomMetrics.wrapped,
    detailZoomOverflow: detailZoomMetrics.scrollWidth - detailZoomMetrics.clientWidth,
    libraryNormalOverflow: normalMetrics.scrollWidth - normalMetrics.clientWidth,
    libraryTouchTargets,
    libraryInternalOverflowAt200Percent: libraryZoomMetrics.internalOverflow,
    libraryZoomOverflow: libraryZoomMetrics.scrollWidth - libraryZoomMetrics.clientWidth,
  }).toEqual({
    detailNormalOverflow: 0,
    detailTouchTargets: [],
    detailKoreanControlWordBreak: [],
    detailWrappedAt200Percent: [],
    detailZoomOverflow: 0,
    libraryNormalOverflow: 0,
    libraryTouchTargets: [],
    libraryInternalOverflowAt200Percent: [],
    libraryZoomOverflow: 0,
  });
  expect(browserErrors).toEqual([]);
});
