/*
 * Workspace, Run view, Artifact library and provenance — real API throughout.
 *
 * The Project, the Run, and the four Artifact Versions this suite reads were
 * produced by the real workbench chain in the fixture: `approve_analysis` then
 * `run_analysis` executed the actual deterministic analysis and committed the
 * outputs, so every digest asserted below was computed by the store, not by a
 * test author.
 */

import { axeSerious, expect, open, test, watchConsole } from "./local-harness.js";

test("the workspace lists the real project and creates another", async ({ app, local }) => {
  const errors = watchConsole(app);
  await open(app, local, "/workspace");

  await expect(app.getByRole("heading", { level: 1, name: "프로젝트" })).toBeVisible();
  await expect(app.locator(`[data-project="${local.project_id}"]`)).toContainText(local.project_name);

  await app.getByLabel("새 프로젝트 이름").fill("두 번째 연구");
  await app.getByRole("button", { name: "프로젝트 만들기" }).click();
  await expect(app.getByRole("link", { name: "두 번째 연구" })).toBeVisible();

  expect(errors).toEqual([]);
});

test("a name the server refuses is reported by its exact reason", async ({ app, local }) => {
  await open(app, local, "/workspace");
  await app.getByLabel("새 프로젝트 이름").fill("보고서/2026");
  await app.getByRole("button", { name: "프로젝트 만들기" }).click();
  await expect(app.getByRole("alert")).toContainText("이름에 경로 구분자를 쓸 수 없습니다");

  await app.getByLabel("새 프로젝트 이름").fill(" 앞뒤 공백 ");
  await app.getByRole("button", { name: "프로젝트 만들기" }).click();
  await expect(app.getByRole("alert")).toContainText("이름 앞뒤에 공백이 있습니다");
});

test("sessions can be created, resumed and archived from the project view", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}`);
  await expect(app.getByRole("heading", { level: 1, name: local.project_name })).toBeVisible();
  await expect(app.getByText("아직 세션이 없습니다")).toBeVisible();

  await app.getByLabel("새 세션 제목").fill("3차 프로브 재분석");
  await app.getByRole("button", { name: "세션 시작" }).click();
  const row = app.locator(".object-row", { hasText: "3차 프로브 재분석" });
  await expect(row).toBeVisible();
  await expect(row).toContainText("활성");

  await row.getByRole("button", { name: "3차 프로브 재분석 세션 이어서 열기" }).click();
  await expect(app.locator("#live-region")).toContainText("이어서 열었습니다");

  // Archiving is destructive, so one click only arms it.
  await row.getByRole("button", { name: "3차 프로브 재분석 세션 보관" }).click();
  await expect(row).toContainText("활성");
  // The armed state must be announced, not only drawn: the accessible name has
  // to change with the visible label or a screen reader never learns that the
  // second press is a confirmation.
  await app.getByRole("button", { name: "3차 프로브 재분석 세션 보관 확인: 한 번 더 누르세요" }).click();
  await expect(app.locator(".object-row", { hasText: "3차 프로브 재분석" })).toContainText("보관됨");
});

test("the artifact library shows the four real outputs of the seeded run", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/artifacts`);
  await expect(app.getByRole("heading", { level: 1, name: "아티팩트 라이브러리" })).toBeVisible();

  for (const artifact of local.artifacts) {
    await expect(app.getByRole("link", { name: artifact.name })).toBeVisible();
  }
  await expect(app.locator(".object-row")).toHaveCount(local.artifacts.length);
});

test("a version row shows the checksum the store actually computed", async ({ app, local }) => {
  const csv = local.artifacts.find((item) => item.role === "csv");
  if (!csv) throw new Error("the fixture did not seed a csv output");

  await open(app, local, `/projects/${local.project_id}/artifacts/${csv.artifact_id}`);
  await expect(app.getByRole("heading", { level: 1, name: csv.name })).toBeVisible();

  const row = app.locator(`tr[data-version="${csv.version_id}"]`);
  await expect(row).toContainText(`v${csv.version_no}`);
  await expect(row).toContainText("불변");
  await expect(row).toContainText(csv.media_type);
  await expect(row).toContainText(csv.content_sha256);
});

test("downloading a version yields exactly the bytes the checksum names", async ({ app, local }) => {
  const csv = local.artifacts.find((item) => item.role === "csv");
  if (!csv) throw new Error("the fixture did not seed a csv output");

  await open(app, local, `/projects/${local.project_id}/artifacts/${csv.artifact_id}`);
  const [download] = await Promise.all([
    app.waitForEvent("download"),
    app.getByRole("button", { name: `버전 ${csv.version_no} 내려받기` }).click(),
  ]);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const bytes = Buffer.concat(chunks);

  expect(bytes.byteLength).toBe(csv.size_bytes);
  const { createHash } = await import("node:crypto");
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(csv.content_sha256);
  expect(download.suggestedFilename()).toContain(`v${csv.version_no}`);
});

test("provenance pins every recomputable digest and discloses in-process isolation", async ({ app, local }) => {
  const markdown = local.artifacts.find((item) => item.role === "markdown");
  if (!markdown) throw new Error("the fixture did not seed a markdown output");

  await open(
    app,
    local,
    `/projects/${local.project_id}/artifacts/${markdown.artifact_id}/versions/${markdown.version_id}`,
  );

  const panel = app.locator(`[data-provenance="${markdown.version_id}"]`);
  await expect(panel).toBeVisible();
  await expect(panel).toContainText(markdown.content_sha256);
  await expect(panel).toContainText(local.execution_id);
  await expect(panel).toContainText("local_deterministic");

  // The honest disclosure, and the absence of any confinement claim.
  const disclosure = panel.locator('[data-isolation="in_process"]');
  await expect(disclosure).toBeVisible();
  await expect(disclosure).toContainText("격리 없음");
  await expect(disclosure).toContainText("연구자 계정의 권한을 그대로 가지며");
  await expect(panel).not.toContainText("샌드박스에서");
  await expect(app.getByText(/샌드박스됨|안전하게 격리|보호된 환경/u)).toHaveCount(0);

  // Empty provenance fields say they are empty rather than being hidden.
  await expect(panel).toContainText("스킬 내용 해시");
  await expect(panel).toContainText("기록된 값 없음");
});

test("the run view lists the outputs in the normative chain order", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs`);
  await expect(app.getByRole("heading", { level: 1, name: "실행 기록" })).toBeVisible();
  await expect(app.locator(`[data-run="${local.run_id}"]`)).toContainText("완료");

  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  const outputs = app.locator(".run-output");
  await expect(outputs).toHaveCount(4);
  await expect(outputs.nth(0)).toContainText("정규화 데이터 (CSV)");
  await expect(outputs.nth(1)).toContainText("그림 (PNG)");
  await expect(outputs.nth(2)).toContainText("해석 노트 (Markdown)");
  await expect(outputs.nth(3)).toContainText("증거 원장 (JSON)");

  // Each row carries the digest the store computed for that exact version.
  for (const artifact of local.artifacts) {
    await expect(app.locator(`.run-output[data-role="${artifact.role}"]`)).toContainText(
      artifact.content_sha256,
    );
  }

  // The run's own isolation is disclosed on the run, not only on provenance.
  const disclosure = app.locator('[data-isolation="in_process"]');
  await expect(disclosure).toContainText("execution_isolation = in_process");
  await expect(disclosure).toContainText("별도의 샌드박스 없이");

  // "샌드박스" may appear only inside that denial. No badge claims one, and no
  // sentence asserts confinement the product does not measure.
  await expect(app.locator(".badge", { hasText: "샌드박스" })).toHaveCount(0);
  await expect(app.locator(".badge", { hasText: "격리" })).toHaveCount(0);
  await expect(
    app.getByText(/샌드박스에서 실행|샌드박스됨|안전하게 격리|격리되어 있습니다|보호된 환경/u),
  ).toHaveCount(0);
});

test("an output links to the provenance of the version it committed", async ({ app, local }) => {
  const png = local.artifacts.find((item) => item.role === "png");
  if (!png) throw new Error("the fixture did not seed a png output");

  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  await app.locator('.run-output[data-role="png"]').getByRole("link", { name: /출처 보기/u }).click();
  await expect(app.locator(`[data-provenance="${png.version_id}"]`)).toBeVisible();
  await expect(app.locator(`[data-provenance="${png.version_id}"]`)).toContainText(png.content_sha256);
});

test("an unknown run is a plain not-found, not a stack trace", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/00000000-0000-7000-8000-000000000000`);
  await expect(app.getByRole("alert")).toContainText("요청한 대상을 찾을 수 없습니다");
});

test("keyboard-only navigation reaches the run view from the workspace", async ({ app, local }) => {
  await open(app, local, "/workspace");
  const link = app.locator(`[data-project="${local.project_id}"]`).getByRole("link", { name: "실행" });
  let reached = false;
  for (let step = 0; step < 60 && !reached; step += 1) {
    await app.keyboard.press("Tab");
    reached = await link.evaluate((node) => node === document.activeElement);
  }
  expect(reached).toBe(true);
  await app.keyboard.press("Enter");
  await expect(app.getByRole("heading", { level: 1, name: "실행 기록" })).toBeVisible();
});

test("every screen keeps one h1, a live region, and no serious axe violation", async ({ app, local }) => {
  const png = local.artifacts.find((item) => item.role === "png");
  if (!png) throw new Error("the fixture did not seed a png output");
  const routes = [
    "/workspace",
    `/projects/${local.project_id}`,
    `/projects/${local.project_id}/artifacts`,
    `/projects/${local.project_id}/artifacts/${png.artifact_id}/versions/${png.version_id}`,
    `/projects/${local.project_id}/runs`,
    `/projects/${local.project_id}/runs/${local.run_id}`,
    `/projects/${local.project_id}/runs/${local.run_id}/export`,
  ];
  for (const route of routes) {
    await open(app, local, route);
    await expect(app.locator("h1"), `one h1 on ${route}`).toHaveCount(1);
    await expect(app.locator("main#main-content")).toHaveCount(1);
    const violations = await axeSerious(app);
    expect(violations, `${route}\n${JSON.stringify(violations, null, 2)}`).toEqual([]);
  }
});

test("no screen scrolls the page horizontally", async ({ app, local }) => {
  const ledger = local.artifacts.find((item) => item.role === "ledger");
  if (!ledger) throw new Error("the fixture did not seed a ledger output");
  const routes = [
    "/settings/models",
    "/workspace",
    `/projects/${local.project_id}/artifacts/${ledger.artifact_id}/versions/${ledger.version_id}`,
    `/projects/${local.project_id}/runs/${local.run_id}`,
    `/projects/${local.project_id}/runs/${local.run_id}/export`,
  ];
  for (const route of routes) {
    await open(app, local, route);
    const overflow = await app.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, `horizontal overflow on ${route}`).toBeLessThanOrEqual(1);
  }
});

test("no API request in this suite was answered by the harness", async ({ app, local }) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  await expect(app.locator(".run-output")).toHaveCount(4);
  expect(local.fulfilledByHarness).toEqual([]);
  expect(local.requestedPaths).toContain("/");
  expect(local.apiResponseBodies.length).toBeGreaterThan(0);
});
