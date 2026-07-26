/*
 * Export, driven through the browser against the real listener.
 *
 * `exportpack.py` shipped complete, tested, and unreachable: Export was the one
 * stage of the ordered chain with no route and no screen. These tests are the
 * proof that it is now reachable *and* that reaching it did not cost anything
 * the surrounding controls guarantee.
 *
 * The download is the part worth being suspicious of. A UI can very easily
 * "succeed" at a download that produced nothing -- the click fires, the promise
 * resolves, and a zero-byte file lands on disk. So nothing here trusts the
 * click. The bytes Chromium wrote are read back off the filesystem, the ZIP is
 * parsed by hand, every digest is recomputed with `node:crypto`, and both of
 * the pack's independent statements about every member have to agree with what
 * was actually received. That check found a real defect during development: the
 * first implementation used Starlette's `StreamingResponse`, whose disconnect
 * listener always wins against this listener's one-request-per-connection
 * server, and every download was 200 OK with an empty body.
 */

import { readFile } from "node:fs/promises";
import { axeSerious, expect, open, test, watchConsole } from "./local-harness.js";
import { sha256, verifyPack } from "./pack-verify.js";

const EXPORT_ROUTE = (project: string, run: string) => `/projects/${project}/runs/${run}/export`;

/** Produce a pack through the UI and return the pack identifier it reports. */
async function produce(app: import("@playwright/test").Page): Promise<string> {
  await app.getByRole("button", { name: "재현성 팩 만들기" }).click();
  const panel = app.locator("[data-pack-id]");
  await expect(panel).toBeVisible();
  return (await panel.getAttribute("data-pack-id")) ?? "";
}

/** Click 팩 내려받기 and return the bytes Chromium actually wrote to disk. */
async function download(app: import("@playwright/test").Page): Promise<Buffer> {
  const started = app.waitForEvent("download");
  await app.getByRole("button", { name: "팩 내려받기" }).click();
  const file = await started;
  const path = await file.path();
  return readFile(path);
}

test("the export screen offers the versions this run pinned, never a latest", async ({
  app,
  local,
}) => {
  const errors = watchConsole(app);
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));

  await expect(app.getByRole("heading", { level: 1, name: "재현성 팩 만들기" })).toBeVisible();
  await expect(app.locator("[data-export-pinning]")).toContainText(
    "내보내기는 아티팩트의 '최신' 버전을 대신 찾지 않습니다",
  );

  // One row per committed output, each naming the exact Version identifier the
  // run recorded. A screen that offered an Artifact without its Version would
  // be the "latest at pack time" race in the UI instead of in the API.
  const rows = app.locator(".export-choice");
  await expect(rows).toHaveCount(local.artifacts.length);
  for (const artifact of local.artifacts) {
    const row = app.locator(`.export-choice:has(input[data-version="${artifact.version_id}"])`);
    await expect(row).toContainText(artifact.version_id);
    await expect(row).toContainText(artifact.content_sha256);
    await expect(row).toContainText(`artifacts/${artifact.name}`);
    await expect(row.locator("input[type=checkbox]")).toBeChecked();
  }
  expect(errors).toEqual([]);
  expect(local.fulfilledByHarness).toEqual([]);
});

test("a produced pack is downloaded by the browser and verifies from its own bytes", async ({
  app,
  local,
}) => {
  const errors = watchConsole(app);
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  const packId = await produce(app);
  expect(packId).not.toEqual("");

  const archive = await download(app);
  // Not a stub, not a blob the page assembled: these are the bytes the browser
  // received over the socket and wrote to the filesystem.
  expect(archive.length).toBeGreaterThan(1024);

  const result = verifyPack(archive);
  expect(result.problems, JSON.stringify(result.problems, null, 2)).toEqual([]);
  expect(result.manifest.schema).toEqual("nipo.local.export-pack.v1");
  expect(result.manifest.pack_id).toEqual(packId);
  expect(result.manifest.selection.resolution).toEqual("explicit_version_ids_never_latest");

  // Every seeded Artifact Version travelled, and its bytes still hash to the
  // digest the store recorded when the run committed it.
  for (const artifact of local.artifacts) {
    const path = `artifacts/${artifact.name}`;
    expect(result.memberPaths).toContain(path);
    expect(result.recomputed.get(path)).toEqual(artifact.content_sha256);
  }
  expect([...result.manifest.selection.artifact_version_ids].sort()).toEqual(
    local.artifacts.map((item) => item.version_id).sort(),
  );

  // The pack must carry no credential material of any kind. The session token
  // is the one secret this browser holds, so it is the sharpest thing to look
  // for in what left the machine.
  expect(archive.includes(Buffer.from(local.token, "utf8"))).toBe(false);
  expect(errors).toEqual([]);
  expect(local.fulfilledByHarness).toEqual([]);
});

test("the screen shows only the versions the researcher kept selected", async ({ app, local }) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  const dropped = local.artifacts[1];
  if (!dropped) throw new Error("the fixture seeded fewer outputs than this test needs");
  await app.locator(`input[data-version="${dropped.version_id}"]`).uncheck();
  await expect(app.locator("[data-selection-count]")).toContainText(
    `${String(local.artifacts.length - 1)}개`,
  );

  await produce(app);
  const archive = await download(app);
  const result = verifyPack(archive);

  expect(result.problems, JSON.stringify(result.problems, null, 2)).toEqual([]);
  expect(result.memberPaths).not.toContain(`artifacts/${dropped.name}`);
  expect(result.manifest.selection.artifact_version_ids).not.toContain(dropped.version_id);
  expect(result.manifest.selection.artifact_version_ids).toHaveLength(local.artifacts.length - 1);
  // The rendered pinned list is the pack's, not a copy the page kept.
  await expect(app.locator(`[data-pinned="${dropped.version_id}"]`)).toHaveCount(0);
});

test("clearing every version disables producing rather than exporting everything", async ({
  app,
  local,
}) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  for (const artifact of local.artifacts) {
    await app.locator(`input[data-version="${artifact.version_id}"]`).uncheck();
  }

  await expect(app.getByRole("button", { name: "재현성 팩 만들기" })).toBeDisabled();
  await expect(app.locator("[data-selection-count]")).toContainText("0개");
  await expect(app.locator("[data-pack-id]")).toHaveCount(0);
});

test("the produced pack's own disclosures are what the screen renders", async ({ app, local }) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  await produce(app);

  // in_process, stated as the absence of isolation it is. There is no branch
  // in the UI that turns this into a sandbox badge, and this asserts the
  // absence rather than assuming it.
  const disclosure = app.locator('[data-isolation="in_process"]');
  await expect(disclosure).toBeVisible();
  await expect(disclosure).toContainText("격리 없음");
  await expect(disclosure).toContainText("execution_isolation = in_process");
  await expect(disclosure).toContainText("별도의 샌드박스 없이");
  // The word appears only where it is denied. What must not exist anywhere is
  // a badge -- of any tone -- that turns the denial into a claim.
  await expect(app.locator('[data-sandbox-claim="false"]')).toBeVisible();
  await expect(app.locator('[data-sandbox-claim="true"]')).toHaveCount(0);
  await expect(app.locator(".badge", { hasText: "샌드박스" })).toHaveCount(0);
  await expect(app.locator(".badge--positive", { hasText: "격리" })).toHaveCount(0);

  // A digest the pack cannot recompute is labelled self-reported and is not
  // shown among the ones it can. The store now records the canonical intent
  // and input bytes against the producing execution, so those two digests
  // recompute from the pack. Only code_sha256 stays self-reported: it is taken
  // over source files, which are not artifacts and are never exported.
  const selfReported = app.locator("[data-self-reported]");
  await expect(selfReported).toContainText("자체 보고");
  await expect(selfReported.locator('[data-digest="code_sha256"]')).toBeVisible();
  await expect(selfReported.locator('[data-digest="research_intent_sha256"]')).toHaveCount(0);
  await expect(selfReported.locator('[data-digest="input_sha256"]')).toHaveCount(0);
  const recomputable = app.locator("[data-recomputable]");
  await expect(recomputable.locator('[data-digest="code_sha256"]')).toHaveCount(0);
  await expect(recomputable.locator('[data-digest="research_intent_sha256"]')).toBeVisible();
  await expect(recomputable.locator('[data-digest="input_sha256"]')).toBeVisible();
  await expect(recomputable.locator('[data-digest="entry_sha256"]')).toBeVisible();

  // No screen in this product says a bare 검증됨.
  await expect(app.getByText("검증됨", { exact: true })).toHaveCount(0);

  // The pack a colleague receives says the same thing, in the same words.
  const archive = await download(app);
  const result = verifyPack(archive);
  expect(result.manifest.disclosures.execution_isolation).toEqual("in_process");
  expect(result.manifest.disclosures.execution_isolation_is_a_sandbox).toBe(false);
  const absent = result.manifest.verification.not_recomputable_from_pack as Record<string, string>;
  expect(Object.keys(absent).sort()).toEqual(["code_sha256"]);
});

test("the pack document table reports inclusion for every reserved document", async ({
  app,
  local,
}) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  await produce(app);

  await expect(app.locator('[data-document="manifest.json"]')).toHaveAttribute(
    "data-included",
    "true",
  );
  await expect(app.locator('[data-document="checksums.sha256"]')).toHaveAttribute(
    "data-included",
    "true",
  );
  // The store records the canonical ResearchIntent and scientific-input bytes
  // against the producing execution and re-verifies them against the pinned
  // digest on the way out, so both documents travel and the table must say so.
  const intent = app.locator('[data-document="research-intent.json"]');
  await expect(intent).toHaveAttribute("data-included", "true");
  await expect(intent).not.toContainText("담기지 않음");
  const input = app.locator('[data-document="scientific-input.json"]');
  await expect(input).toHaveAttribute("data-included", "true");

  const archive = await download(app);
  const result = verifyPack(archive);
  expect(result.memberPaths).toContain("research-intent.json");
  expect(result.memberPaths).toContain("scientific-input.json");
  expect(result.memberPaths).toContain("manifest.json");
});

test("the capability the browser used is spent, scoped, and never in the address bar", async ({
  app,
  local,
}) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  const packId = await produce(app);

  const started = app.waitForEvent("download");
  await app.getByRole("button", { name: "팩 내려받기" }).click();
  const file = await started;
  // Chromium performs a download outside the page, so this URL is the only
  // record of the capability the browser really used. Everything below is
  // asserted against that exact string.
  const used = file.url();
  expect(used).toContain(`/exports/${packId}/content/`);
  expect((await readFile(await file.path())).length).toBeGreaterThan(1024);

  // The capability lives in a URL because a download navigation cannot carry a
  // header. It must therefore be nowhere a URL normally persists.
  expect(app.url()).not.toContain("/content/");
  expect(app.url()).toContain("#/projects/");
  expect(
    await app.evaluate(() => ({
      anchors: [...document.querySelectorAll("a")].filter((node) =>
        node.getAttribute("href")?.includes("/content/"),
      ).length,
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ anchors: 0, local: [], session: [] });

  // Replaying the exact URL is refused. This is also the proof that the
  // browser's download really went through the guard: only an accepted
  // capability becomes a spent one.
  const replay = await app.request.get(used, { headers: { "Sec-Fetch-Site": "same-origin" } });
  expect(replay.status()).toBe(401);
  expect(await replay.json()).toEqual({ error: "download_ticket_spent" });

  // The session credential does not substitute for a capability: the guard is
  // the only authority on who may read a pack, and a guessed URL carries no
  // capability for it to have accepted.
  const guessed = used.replace(/\/content\/[^/]+$/u, "/content/not-a-real-capability");
  const forged = await app.request.get(guessed, {
    headers: { "X-Nipo-Token": local.token, "Sec-Fetch-Site": "same-origin" },
  });
  expect(forged.status()).toBe(401);
  expect(await forged.json()).toEqual({ error: "download_ticket_invalid" });
});

test("a fresh capability is scoped to one pack and cannot carry a Referer", async ({
  app,
  local,
}) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  const packId = await produce(app);

  const minted = await app.request.post(
    `${local.origin}/api/v1/projects/${local.project_id}/exports/${packId}/download`,
    {
      headers: {
        "X-Nipo-Token": local.token,
        Origin: local.origin,
        "Sec-Fetch-Site": "same-origin",
      },
    },
  );
  expect(minted.status()).toBe(201);
  const grant = (await minted.json()) as {
    url: string;
    expires_at: string;
    expires_in_seconds: number;
    single_use: boolean;
  };
  expect(grant.single_use).toBe(true);
  expect(grant.expires_in_seconds).toBe(60);
  expect(Date.parse(grant.expires_at)).toBeGreaterThan(Date.now());
  expect(grant.url).toContain(`/exports/${packId}/content/`);
  // A capability is not the session credential and must not be mistakable for
  // one: nothing in the URL is the token this page authenticates with.
  expect(grant.url).not.toContain(local.token);

  // Scoped: the same secret presented at another pack's path opens nothing.
  const elsewhere = grant.url.replace(`/exports/${packId}/`, "/exports/019f0000-0000-7000-8000-00000000beef/");
  const wrongPack = await app.request.get(`${local.origin}${elsewhere}`, {
    headers: { "Sec-Fetch-Site": "same-origin" },
  });
  expect(wrongPack.status()).toBe(401);
  expect(await wrongPack.json()).toEqual({ error: "download_ticket_invalid" });

  // A cross-site load of a capability URL is refused even though a GET is not
  // state-changing, because a capability is screened under the same
  // fetch-metadata rule the document surface gets rather than the looser one.
  const crossSite = await app.request.get(`${local.origin}${grant.url}`, {
    headers: { "Sec-Fetch-Site": "cross-site" },
  });
  expect(crossSite.status()).toBe(403);
  expect(await crossSite.json()).toEqual({ error: "cross_origin_denied" });

  // The capability sits in a URL, so what keeps it out of a `Referer` is the
  // policy every response from this listener carries. The document that mints
  // it and the response that spends it both carry it, and the document's CSP
  // permits no off-origin subresource that could emit one in the first place.
  const spend = await app.request.get(`${local.origin}${grant.url}`, {
    headers: { "Sec-Fetch-Site": "same-origin" },
  });
  expect(spend.status()).toBe(200);
  expect(spend.headers()["referrer-policy"]).toBe("no-referrer");
  expect(spend.headers()["content-disposition"]).toContain("attachment");
  const document = await app.request.get(`${local.origin}/`);
  expect(document.headers()["referrer-policy"]).toBe("no-referrer");
  expect(document.headers()["content-security-policy"]).toContain("default-src 'none'");
});

test("a second download mints a fresh capability instead of reusing one", async ({
  app,
  local,
}) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  await produce(app);

  const first = await download(app);
  const second = await download(app);

  expect(sha256(second)).toEqual(sha256(first));
  const result = verifyPack(second);
  expect(result.problems, JSON.stringify(result.problems, null, 2)).toEqual([]);
});

test("the whole export is reachable from the run screen with the keyboard alone", async ({
  app,
  local,
}) => {
  await open(app, local, `/projects/${local.project_id}/runs/${local.run_id}`);
  await app.locator('[data-action="open-export"]').focus();
  await app.keyboard.press("Enter");
  await expect(app.getByRole("heading", { level: 1, name: "재현성 팩 만들기" })).toBeVisible();

  // Toggle one Version off with the space bar, then produce with Enter.
  const first = local.artifacts[0];
  if (!first) throw new Error("the fixture seeded no outputs");
  const box = app.locator(`input[data-version="${first.version_id}"]`);
  await box.focus();
  await app.keyboard.press("Space");
  await expect(box).not.toBeChecked();
  await app.getByRole("button", { name: "재현성 팩 만들기" }).focus();
  await app.keyboard.press("Enter");
  await expect(app.locator("[data-pack-id]")).toBeVisible();

  const started = app.waitForEvent("download");
  await app.getByRole("button", { name: "팩 내려받기" }).focus();
  await app.keyboard.press("Enter");
  const archive = await readFile(await (await started).path());
  const result = verifyPack(archive);
  expect(result.problems, JSON.stringify(result.problems, null, 2)).toEqual([]);
  expect(result.memberPaths).not.toContain(`artifacts/${first.name}`);
});

test("the export screens are accessible before and after a pack exists", async ({ app, local }) => {
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  const before = await axeSerious(app);
  expect(before, JSON.stringify(before, null, 2)).toEqual([]);

  await produce(app);
  const after = await axeSerious(app);
  expect(after, JSON.stringify(after, null, 2)).toEqual([]);

  // The produced state is the widest thing this screen ever shows -- a table of
  // 64-character digests -- and it still may not push the page sideways.
  await expect(app.locator("h1")).toHaveCount(1);
  const overflow = await app.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});

test.describe("with the Run seam unbound, as a stock install ships", () => {
  test.use({ runSurface: false });

  test("the export route is still honest rather than blank", async ({ app, local }) => {
    // The Run surface is a read seam; Export reads the store directly, so it
    // keeps working. What must not happen is a screen that silently offers
    // nothing, so the run's own outputs still have to be listed.
    await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
    await expect(app.locator(".export-choice")).toHaveCount(local.artifacts.length);
    await expect(app.getByRole("alert")).toBeHidden();
  });
});
