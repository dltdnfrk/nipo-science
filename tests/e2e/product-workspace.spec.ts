import process from "node:process";
import { expect, test, type Page } from "@playwright/test";
import { authenticateProduct, productOrigin } from "./product-auth.js";

const productSessionId = "018f0d7d-6b17-7a91-8b31-2f7331677c01";

test.beforeEach(async ({ page }) => {
  await authenticateProduct(page);
});

async function collectViaChat(page: Page, prompt = "정규화 연구 3개") {
  await page.goto(`${productOrigin}/upload`);
  await page.locator("#collect-prompt").fill(prompt);
  await page.getByRole("button", { name: "수집 계획" }).click();
  await page.getByRole("button", { name: "이대로 수집" }).click();
  await expect(page.locator(".collect-results")).toBeVisible();
}

async function createRunPendingApproval(page: Page): Promise<string> {
  await page.goto(`${productOrigin}/upload`);
  await page.locator(".adv-opts > summary").first().click();
  await page.locator("#dry-lab-file").setInputFiles({
    name: "calibrated-workspace.csv",
    mimeType: "text/csv",
    buffer: Buffer.from("sample,value,calibration\na,1.0,cal-1\n"),
  });
  await page.locator("#research-question").fill("워크스페이스 폴 갱신을 검증할 수 있는가?");
  await page.locator("#research-rationale").fill("서버 단계 변화가 화면에 반영되는지 확인한다.");
  await page.locator("#research-benefit").fill("항상 최신 상태의 작업 허브를 만든다.");
  await page.locator("#research-success-criteria").fill("승인 후 단계 라벨이 바뀐다.");
  await page.locator("#research-constraints").fill("비임상 연구 데이터만 사용한다.");
  await page.locator("#research-stop-conditions").fill("폴이 멈추면 중단한다.");
  await page.locator("#research-mode").selectOption("bounded_agentic");
  await page.locator("#research-data-origin").selectOption("observed");
  await page.locator("#dry-lab-session").selectOption(productSessionId);
  await page.locator("#dry-lab-prompt").fill("워크스페이스 폴 검증 실행.");
  await page.getByRole("button", { name: "연구 시작하기" }).click();
  await expect(page.getByRole("heading", { name: "ActionPlan 승인" })).toBeVisible();
  return page.url();
}

test("workspace lists past collections and reopens the results table", async ({ page }) => {
  const browserErrors: string[] = [];
  page.on("pageerror", (error) => browserErrors.push(error.message));

  await collectViaChat(page);
  await page.goto(`${productOrigin}/workspace`);

  const history = page.locator('[aria-label="지난 수집"]');
  await expect(history).toBeVisible();
  const item = history.locator(".collection-history-open").first();
  await expect(item).toHaveText("정규화 연구");
  await expect(history).toContainText("3건");

  await item.click();
  const table = page.locator(".collect-table");
  await expect(table).toBeVisible();
  await expect(table.locator("tbody tr")).toHaveCount(3);

  await page.getByRole("button", { name: "목록으로" }).click();
  await expect(history.locator(".collection-history-open").first()).toBeVisible();
  expect(browserErrors).toEqual([]);
});

test("next-action card deep-links to the pending approval", async ({ page }) => {
  await createRunPendingApproval(page);

  await page.goto(`${productOrigin}/workspace`);
  const card = page.locator('[aria-label="지금 할 일"]');
  await expect(card).toBeVisible();
  // 다른 승인 대기 run이 남아 있어도 승인 페이지로 바로 연결된다
  await expect(card.getByRole("link", { name: "계획 승인 보기" })).toHaveAttribute(
    "href",
    /^\/runs\/[0-9a-f-]+\/approval$/u,
  );
});

test("workspace poll reflects stage changes approved in another tab", async ({ page, context }) => {
  const approvalUrl = await createRunPendingApproval(page);
  const runId = new URL(approvalUrl).pathname.split("/")[2];

  await page.goto(`${productOrigin}/workspace`);
  const recentItem = page.locator(`[data-run-id="${runId}"]`);
  await expect(recentItem).toContainText("계획 승인 대기");

  const second = await context.newPage();
  await authenticateProduct(second);
  await second.goto(approvalUrl);
  await second.getByRole("button", { name: "계획 승인" }).click();
  await expect(second.getByRole("button", { name: "승인된 계획 실행" })).toBeVisible();

  // 기본 5초 폴이 서버 단계 변화를 워크스페이스에 반영한다
  await expect(recentItem).toContainText("계획 승인 완료", { timeout: 15000 });
  await second.close();
});
