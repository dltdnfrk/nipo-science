/*
 * The Review screen, against a real Review of a real run.
 *
 * `reviewer.py` was complete and invisible: it had no route and no screen, so
 * a verdict it reached could not be read by the researcher it was for. These
 * tests cover the seam and the three UI rules that make a verdict honest:
 *
 *   - there is no bare "검증됨" badge anywhere;
 *   - every verdict is rendered together with what the rule did *not* check;
 *   - `inconclusive` is presented as a normal outcome, not an error.
 *
 * Nothing here is stubbed. The POST runs the real Reviewer over the evidence
 * the seeded run really pinned, and the store really persists it.
 */

import { axeSerious, expect, open, test } from "./local-harness.js";

const RULES = ["RV01", "RV02", "RV03", "RV04", "RV05"];

test("an unreviewed run says so instead of implying it passed", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);

  await expect(app.getByRole("heading", { level: 1, name: "아직 검토하지 않은 실행입니다" })).toBeVisible();
  await expect(app.getByText("이 실행에는 검토 기록이 없습니다")).toBeVisible();
  // The two lies available here: a pass badge, or an empty findings list that
  // reads as "reviewed, nothing wrong".
  await expect(app.locator(".badge", { hasText: "검증됨" })).toHaveCount(0);
  await expect(app.locator(".badge", { hasText: "위반 없음" })).toHaveCount(0);
  await expect(app.locator(".review-finding")).toHaveCount(0);
});

test("running a review records every rule with its verdict and its limits", async ({
  app,
  local,
}) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);
  await app.getByRole("button", { name: "검토 실행" }).click();

  await expect(app.getByRole("heading", { level: 1, name: "추적 전용 검토" })).toBeVisible();
  const findings = app.locator(".review-finding");
  await expect(findings).toHaveCount(RULES.length);

  for (const rule of RULES) {
    const card = app.locator(`.review-finding[data-rule="${rule}"]`);
    await expect(card, rule).toBeVisible();
    // A verdict is never shown without the boundary that qualifies it.
    await expect(card.locator('[data-coverage="unchecked"]'), rule).toBeVisible();
    await expect(card.locator('[data-coverage="unchecked"] li'), rule).not.toHaveCount(0);
    await expect(card.locator('[data-coverage="checked"] li'), rule).not.toHaveCount(0);
    await expect(card, rule).toContainText("확인하지 않은 것");
    await expect(card, rule).toContainText("확인한 것");
  }

  // The review pinned the exact four Versions the run committed.
  const panel = app.locator("[data-review-id]");
  for (const artifact of local.artifacts) {
    await expect(panel).toContainText(artifact.version_id);
  }
  await expect(panel).toContainText(local.run_id);
});

test("RV02 reaches inconclusive offline and it is styled as a normal outcome", async ({
  app,
  local,
}) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);
  await app.getByRole("button", { name: "검토 실행" }).click();
  await expect(app.locator(".review-finding")).toHaveCount(RULES.length);

  const rv02 = app.locator('.review-finding[data-rule="RV02"]');
  const verdict = await rv02.getAttribute("data-verdict");
  // The default resolver is offline, so RV02 is either inconclusive (an
  // identifier was cited and could not be reached) or a plain pass with no
  // identifier cited. It must never be a manufactured fail.
  expect(["inconclusive", "pass"]).toContain(verdict);

  // Whatever it reached, the screen states the structural limit: this rule
  // cannot tie an identifier to the claim that rests on it.
  await expect(rv02).toContainText("특정 주장이 그 식별자에 근거하는가");
  await expect(rv02).toContainText("판정 보류는 리뷰어의 실패가 아니라");

  // `inconclusive` is not an error state: no alert, and no danger styling.
  await expect(app.getByRole("alert")).toBeHidden();
  await expect(app.locator('.review-finding[data-verdict="inconclusive"].badge--danger')).toHaveCount(0);
});

test("RV01's structural limit is disclosed rather than implied away", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);
  await app.getByRole("button", { name: "검토 실행" }).click();
  await expect(app.locator(".review-finding")).toHaveCount(RULES.length);

  const rv01 = app.locator('.review-finding[data-rule="RV01"]');
  // No pinned machine-readable spectrum output exists, so the per-peak numbers
  // can only be checked against the report that published them.
  await expect(rv01).toContainText("기계 판독 가능한 스펙트럼 산출물이 고정되어 있지");
  await expect(rv01).toContainText("독립된");
});

test("the summary verdict is never a bare badge and the whole limit set is listed", async ({
  app,
  local,
}) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);
  await app.getByRole("button", { name: "검토 실행" }).click();
  await expect(app.locator(".review-finding")).toHaveCount(RULES.length);

  // The one word that would misrepresent this screen.
  await expect(app.getByText("검증됨", { exact: true })).toHaveCount(0);
  await expect(app.locator(".badge", { hasText: "검증됨" })).toHaveCount(0);

  // The verdict panel carries the sentence that bounds the verdict.
  const summary = app.locator("[data-review-verdict]");
  await expect(summary).toBeVisible();
  await expect(summary).toContainText("고정된 증거만 읽습니다");
  await expect(summary).toContainText("파이썬을 실행하지도");

  // Every rule's limits also appear in one consolidated disclosure, so a
  // reader who only looks at the top of the page still sees the boundary.
  const limits = app.locator("[data-review-limits]");
  await expect(limits).toContainText("이 검토가 확인하지 않은 것");
  for (const rule of RULES) {
    await expect(limits, rule).toContainText(rule);
  }
  expect(Number(await limits.getAttribute("data-review-limits"))).toBeGreaterThanOrEqual(RULES.length);
});

test("reviewing twice returns the same Review rather than a second one", async ({ app, local }) => {
  // Deduplication is by pinned evidence, so a researcher who clicks twice
  // cannot end up with two Reviews that disagree about the same bytes.
  const first = await app.request.post(
    `${local.origin}/api/v1/projects/${local.project_id}/runs/${local.run_id}/review`,
    { headers: { "X-Nipo-Token": local.token } },
  );
  expect(first.status()).toBe(201);
  const second = await app.request.post(
    `${local.origin}/api/v1/projects/${local.project_id}/runs/${local.run_id}/review`,
    { headers: { "X-Nipo-Token": local.token } },
  );
  expect(second.status()).toBe(201);

  const one = (await first.json()) as { id: string; pinned_input_sha256: string; verdict: string };
  const two = (await second.json()) as { id: string; pinned_input_sha256: string; verdict: string };
  expect(two.id).toBe(one.id);
  expect(two.pinned_input_sha256).toBe(one.pinned_input_sha256);
  expect(two.verdict).toBe(one.verdict);
});

test("the review route is reachable from the run and stays accessible", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  await app.getByRole("link", { name: "검토 열기" }).click();
  await expect(app.getByRole("heading", { level: 1, name: "아직 검토하지 않은 실행입니다" })).toBeVisible();

  await app.getByRole("button", { name: "검토 실행" }).click();
  await expect(app.locator(".review-finding")).toHaveCount(RULES.length);
  await expect(app.getByRole("heading", { level: 1 })).toHaveCount(1);

  const violations = await axeSerious(app);
  expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
});

test("the review never claims to have re-run anything", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}/review`);
  await app.getByRole("button", { name: "검토 실행" }).click();
  await expect(app.locator(".review-finding")).toHaveCount(RULES.length);

  // No sentence on this screen may assert re-execution, verification of the
  // science itself, or a guarantee the Reviewer cannot give.
  await expect(
    app.getByText(/다시 실행했습니다|재실행했습니다|분석이 옳음을 확인|정확함을 보장/u),
  ).toHaveCount(0);
  // The run's four versions are still exactly four: a review writes nothing.
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  await expect(app.locator(".run-output")).toHaveCount(4);
});
