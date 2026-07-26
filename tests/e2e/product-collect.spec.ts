import process from "node:process";
import { expect, test } from "@playwright/test";
import { authenticateProduct, productOrigin } from "./product-auth.js";

const productSessionId = "018f0d7d-6b17-7a91-8b31-2f7331677c01";

test.beforeEach(async ({ page }) => {
  await authenticateProduct(page);
});

test("chat collection plans, confirms, selects records, and becomes the run input", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));

  // 설정에서 OpenAlex를 연결한다 (해제 → 연결 상태 전이)
  await page.goto(`${productOrigin}/settings/providers`);
  await expect(page.getByRole("heading", { name: "데이터 소스 연결" })).toBeVisible();
  const openAlexCard = page.locator('[data-connector-id="openalex"]');
  // 다른 프로젝트가 같은 픽스처 주체의 상태를 바꿨을 수 있으므로 멱등하게 맞춘다
  if ((await openAlexCard.getByText("해제됨").count()) > 0) {
    await openAlexCard.getByRole("button", { name: "연결", exact: true }).click();
  }
  await expect(openAlexCard.getByText("연결됨")).toBeVisible();

  // 채팅으로 주제를 입력하면 확인 카드가 뜬다
  await page.goto(`${productOrigin}/upload`);
  await page.locator("#collect-prompt").fill("openalex 정규화 연구 3개");
  await page.getByRole("button", { name: "수집 계획" }).click();
  const card = page.locator("#collect-confirm");
  await expect(card).toBeVisible();
  await expect(card).toContainText("OpenAlex");
  await expect(card).toContainText("3건");

  // 확인하면 수집 결과가 선택 가능한 테이블로 렌더된다
  await page.getByRole("button", { name: "이대로 수집" }).click();
  await expect(card).toBeHidden();
  const results = page.locator(".collect-results");
  await expect(results).toBeVisible();
  await expect(results.locator("tbody tr")).toHaveCount(3);
  const materializeButton = page.getByRole("button", { name: /연구 입력 생성/u });
  await expect(materializeButton).toHaveText("선택한 3건으로 연구 입력 생성");

  // 전체 해제하면 생성 버튼이 비활성화된다
  const rowChecks = results.locator(".collect-row-check");
  await rowChecks.nth(0).uncheck();
  await rowChecks.nth(1).uncheck();
  await rowChecks.nth(2).uncheck();
  await expect(materializeButton).toHaveText("선택한 0건으로 연구 입력 생성");
  await expect(materializeButton).toBeDisabled();

  // 하나를 다시 선택하면 버튼이 살아나고, 전체 재선택으로 기존 플로우를 복원한다
  await rowChecks.first().check();
  await expect(materializeButton).toBeEnabled();
  await rowChecks.nth(1).check();
  await rowChecks.nth(2).check();
  await expect(materializeButton).toHaveText("선택한 3건으로 연구 입력 생성");

  // 한 행을 빼면 버튼 라벨이 선택 수를 반영한다
  await results.locator(".collect-row-check").first().uncheck();
  await expect(materializeButton).toHaveText("선택한 2건으로 연구 입력 생성");

  // 선택분을 실체화하면 수집 결과가 연구 입력이 된다
  await materializeButton.click();
  await expect(results).toBeHidden();
  await expect(page.locator("#dry-lab-file-name")).toContainText("수집 결과:");
  await expect(page.locator("#dry-lab-file-name")).toContainText("2건");

  // 파일 업로드 없이 수집 입력으로 연구를 시작한다
  await page.locator(".adv-opts > summary").first().click();
  await page.locator("#research-question").fill("수집된 문헌으로 정규화를 검증할 수 있는가?");
  await page.locator("#research-rationale").fill("수집 입력의 재현성을 확인한다.");
  await page.locator("#research-benefit").fill("문헌 기반 기준선을 만든다.");
  await page.locator("#research-success-criteria").fill("동일 입력은 동일 체크섬을 만든다.");
  await page.locator("#research-constraints").fill("비임상 연구 데이터만 사용한다.");
  await page.locator("#research-stop-conditions").fill("수집 결과가 없으면 중단한다.");
  await page.locator("#research-mode").selectOption("bounded_agentic");
  await page.locator("#research-data-origin").selectOption("observed");
  await page.locator("#dry-lab-session").selectOption(productSessionId);
  await page.locator("#dry-lab-prompt").fill("수집 결과를 정규화한다.");
  await page.getByRole("button", { name: "연구 시작하기" }).click();
  await expect(page.getByRole("heading", { name: "ActionPlan 승인" })).toBeVisible();
  expect(browserErrors).toEqual([]);
});

test("collection cancel keeps the form editable", async ({ page }) => {
  await page.goto(`${productOrigin}/upload`);
  await page.locator("#collect-prompt").fill("정규화 연구 2개");
  await page.getByRole("button", { name: "수집 계획" }).click();
  await expect(page.locator("#collect-confirm")).toBeVisible();
  await page.getByRole("button", { name: "다시 입력" }).click();
  await expect(page.locator("#collect-confirm")).toBeHidden();
  await expect(page.locator("#collect-prompt")).toHaveValue("정규화 연구 2개");
});
