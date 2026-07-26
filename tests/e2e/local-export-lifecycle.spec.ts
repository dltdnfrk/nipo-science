/*
 * The Export Pack lifecycle, driven through the browser against the real
 * listener and checked against the real filesystem.
 *
 * A delete button is the easiest control in a product to make look right and
 * be wrong. The click fires, the row disappears, a toast says it worked, and
 * the file is still sitting on disk -- or, far worse, a *different* file is
 * not. So nothing here trusts the screen: every assertion about what was
 * removed is made by reading `<root>/exports/<project>/` off the filesystem
 * that the fixture handed over in its handshake, before and after, and by
 * digesting the packs that were supposed to survive.
 *
 * Two properties get the most attention because they are the two that would be
 * silently wrong:
 *
 * 1. **One press must not delete.** The armed state is asserted through the
 *    *accessible* name, not the visible label. This codebase has already
 *    shipped that bug once: a two-step control whose `textContent` changed
 *    while its `aria-label` did not, so a screen-reader user heard the same
 *    name twice and pressed a button whose meaning had silently changed.
 * 2. **A sweep must not remove a pack nobody saw.** Every candidate is named
 *    on screen before the sweep is armed, and afterwards the packs that were
 *    *not* candidates are digested and compared byte for byte.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import {
  axeSerious,
  expect,
  open,
  test,
  watchConsole,
  type LocalServer,
} from "./local-harness.js";

const PACKS_ROUTE = (project: string) => `/projects/${project}/exports`;
const EXPORT_ROUTE = (project: string, run: string) => `/projects/${project}/runs/${run}/export`;

/** The directory the fixture's data root really writes packs into. */
function exportsDirectory(local: LocalServer): string {
  return path.join(local.root, "exports", local.project_id);
}

/** Read every pack file that is on disk right now, with its real size. */
function packsOnDisk(local: LocalServer): Map<string, number> {
  const directory = exportsDirectory(local);
  if (!existsSync(directory)) return new Map();
  return new Map(
    readdirSync(directory)
      .filter((name) => name.endsWith(".zip"))
      .map((name) => [name.slice(0, -4), statSync(path.join(directory, name)).size]),
  );
}

/** Digest one pack exactly as it is on disk now. */
function digestOnDisk(local: LocalServer, packId: string): string {
  return createHash("sha256")
    .update(readFileSync(path.join(exportsDirectory(local), `${packId}.zip`)))
    .digest("hex");
}

/**
 * Produce one pack over the real API, using the real session credential.
 *
 * Not a stub and not a fixture write: this is the same request the export
 * screen issues, over the same socket, so the packs a lifecycle test starts
 * from are packs the product really made.
 */
async function seedPack(
  app: import("@playwright/test").Page,
  local: LocalServer,
): Promise<string> {
  const response = await app.request.post(
    `${local.origin}/api/v1/projects/${local.project_id}/runs/${local.run_id}/export`,
    {
      headers: {
        "X-Nipo-Token": local.token,
        Origin: local.origin,
        "Sec-Fetch-Site": "same-origin",
      },
      data: { artifact_version_ids: local.artifacts.map((item) => item.version_id) },
    },
  );
  expect(response.status()).toBe(201);
  return String(((await response.json()) as { pack_id: string }).pack_id);
}

test("a pack produced on the export screen appears on the lifecycle screen", async ({
  app,
  local,
}) => {
  const errors = watchConsole(app);
  await open(app, local, EXPORT_ROUTE(local.project_id, local.run_id));
  await app.getByRole("button", { name: "재현성 팩 만들기" }).click();
  const packId = (await app.locator("[data-pack-id]").getAttribute("data-pack-id")) ?? "";
  expect(packId).not.toEqual("");

  // Reached from the screen that made the file, with the keyboard alone.
  await app.locator('[data-action="open-export-packs"]').focus();
  await app.keyboard.press("Enter");

  await expect(app.getByRole("heading", { level: 1, name: "내보낸 팩" })).toBeVisible();
  const row = app.locator(`[data-pack-row="${packId}"]`);
  await expect(row).toBeVisible();
  await expect(row).toContainText(local.run_id);

  const onDisk = packsOnDisk(local);
  expect([...onDisk.keys()]).toEqual([packId]);
  // The size the screen reports is the size the file really is.
  await expect(row.locator("[data-pack-size]")).toHaveAttribute(
    "data-pack-size",
    String(onDisk.get(packId)),
  );
  await expect(app.locator("[data-exports-total]")).toHaveAttribute(
    "data-exports-total",
    String(onDisk.get(packId)),
  );
  await expect(app.locator("[data-budget-state]")).toHaveAttribute("data-budget-state", "under");
  expect(errors).toEqual([]);
  expect(local.fulfilledByHarness).toEqual([]);
});

test("one press of 지우기 removes nothing and changes the accessible name", async ({
  app,
  local,
}) => {
  const packId = await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  const unarmed = app.getByRole("button", { name: `팩 ${packId} 지우기`, exact: true });
  await expect(unarmed).toBeVisible();
  await unarmed.click();

  // The accessible name is what a screen reader announces, and it must be the
  // thing that changed. `exact` matters: the armed name contains the unarmed
  // one as a prefix, so a substring match would agree with either.
  await expect(
    app.getByRole("button", { name: `팩 ${packId} 지우기`, exact: true }),
  ).toHaveCount(0);
  await expect(
    app.getByRole("button", { name: new RegExp(`팩 ${packId} 지우기 확인`, "u") }),
  ).toBeVisible();

  // Nothing was removed. Asserted against the filesystem, not against the row.
  expect(existsSync(path.join(exportsDirectory(local), `${packId}.zip`))).toBe(true);
  expect([...packsOnDisk(local).keys()]).toEqual([packId]);
  await expect(app.locator(`[data-pack-row="${packId}"]`)).toBeVisible();
});

test("the second press removes the pack and its bytes are gone from disk", async ({
  app,
  local,
}) => {
  const errors = watchConsole(app);
  const doomed = await seedPack(app, local);
  const kept = await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));
  const keptDigest = digestOnDisk(local, kept);
  const before = packsOnDisk(local);
  expect([...before.keys()].sort()).toEqual([doomed, kept].sort());

  const button = app.getByRole("button", { name: `팩 ${doomed} 지우기`, exact: true });
  await button.click();
  await app.getByRole("button", { name: new RegExp(`팩 ${doomed} 지우기 확인`, "u") }).click();

  await expect(app.locator(`[data-pack-row="${doomed}"]`)).toHaveCount(0);
  await expect(app.locator(`[data-pack-row="${kept}"]`)).toBeVisible();

  // The bytes, not the row: the file is really gone from the filesystem.
  expect(existsSync(path.join(exportsDirectory(local), `${doomed}.zip`))).toBe(false);
  const after = packsOnDisk(local);
  expect([...after.keys()]).toEqual([kept]);
  // And the pack that was not named is untouched, byte for byte.
  expect(digestOnDisk(local, kept)).toEqual(keptDigest);
  await expect(app.locator("[data-exports-total]")).toHaveAttribute(
    "data-exports-total",
    String(after.get(kept)),
  );
  expect(errors).toEqual([]);
  expect(local.fulfilledByHarness).toEqual([]);
});

test("a removed pack cannot be downloaded afterwards", async ({ app, local }) => {
  const packId = await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  await app.getByRole("button", { name: `팩 ${packId} 지우기`, exact: true }).click();
  await app.getByRole("button", { name: new RegExp(`팩 ${packId} 지우기 확인`, "u") }).click();
  await expect(app.locator(`[data-pack-row="${packId}"]`)).toHaveCount(0);

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
  expect(minted.status()).toBe(404);
  expect(await minted.json()).toEqual({ error: "export_pack_not_found" });
});

test("the whole removal is reachable with the keyboard alone", async ({ app, local }) => {
  const packId = await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  const button = app.getByRole("button", { name: `팩 ${packId} 지우기`, exact: true });
  await button.focus();
  await app.keyboard.press("Enter");
  expect(existsSync(path.join(exportsDirectory(local), `${packId}.zip`))).toBe(true);

  await app.getByRole("button", { name: new RegExp(`팩 ${packId} 지우기 확인`, "u") }).focus();
  await app.keyboard.press("Enter");

  await expect(app.locator(`[data-pack-row="${packId}"]`)).toHaveCount(0);
  expect(packsOnDisk(local).size).toBe(0);
});

test("a pack can be downloaded straight from the lifecycle screen", async ({ app, local }) => {
  const packId = await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  const started = app.waitForEvent("download");
  await app.getByRole("button", { name: `팩 ${packId} 내려받기`, exact: true }).click();
  const file = await started;

  expect(file.url()).toContain(`/exports/${packId}/content/`);
  const bytes = readFileSync(await file.path());
  expect(bytes.length).toBeGreaterThan(1024);
  // Byte-identical to what is on disk: nothing was re-assembled in the page.
  expect(createHash("sha256").update(bytes).digest("hex")).toEqual(digestOnDisk(local, packId));
});

test("the sweep names every candidate before it is armed and touches nothing else", async ({
  app,
  local,
}) => {
  const produced: string[] = [];
  for (let index = 0; index < 5; index += 1) produced.push(await seedPack(app, local));
  await open(app, local, PACKS_ROUTE(local.project_id));

  const digests = new Map(produced.map((item) => [item, digestOnDisk(local, item)]));
  const rows = await app.locator("[data-pack-row]").evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute("data-pack-row") ?? ""),
  );
  const candidates = await app.locator("[data-sweep-candidate]").evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute("data-sweep-candidate") ?? ""),
  );

  // The newest three are kept, so exactly two are offered -- and every one of
  // them is a row already rendered on this screen. That is the property the
  // whole design rests on: nothing unseen can be swept.
  expect(rows).toHaveLength(5);
  expect(candidates).toHaveLength(2);
  for (const candidate of candidates) expect(rows).toContain(candidate);
  const kept = rows.filter((item) => !candidates.includes(item));
  expect(kept).toHaveLength(3);

  await app.getByRole("button", { name: /오래된 팩 2개 정리$/u }).click();
  await expect(app.getByRole("button", { name: /정리 확인/u })).toBeVisible();
  await app.getByRole("button", { name: /정리 확인/u }).click();

  await expect(app.locator("[data-pack-row]")).toHaveCount(3);
  const after = packsOnDisk(local);
  expect([...after.keys()].sort()).toEqual([...kept].sort());
  for (const survivor of kept) {
    // Not merely present: the same bytes as before the sweep.
    expect(digestOnDisk(local, survivor)).toEqual(digests.get(survivor));
  }
  for (const swept of candidates) {
    expect(existsSync(path.join(exportsDirectory(local), `${swept}.zip`))).toBe(false);
  }
});

test("one press of the sweep removes nothing", async ({ app, local }) => {
  for (let index = 0; index < 4; index += 1) await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));
  const before = packsOnDisk(local);

  await app.getByRole("button", { name: /오래된 팩 1개 정리$/u }).click();

  await expect(app.getByRole("button", { name: /오래된 팩 1개 정리$/u })).toHaveCount(0);
  await expect(app.getByRole("button", { name: /정리 확인/u })).toBeVisible();
  expect([...packsOnDisk(local).keys()].sort()).toEqual([...before.keys()].sort());
  await expect(app.locator("[data-pack-row]")).toHaveCount(4);
});

test("a project with three or fewer packs is offered no sweep at all", async ({ app, local }) => {
  for (let index = 0; index < 3; index += 1) await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  await expect(app.locator("[data-sweep-candidate]")).toHaveCount(0);
  await expect(app.locator('[data-sweep-candidates="0"]')).toBeVisible();
  await expect(app.getByRole("button", { name: /정리$/u })).toHaveCount(0);
});

test("the screen states that nothing expires and nothing is swept for you", async ({
  app,
  local,
}) => {
  await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));

  const retention = app.locator('[data-retention="none"]');
  await expect(retention).toBeVisible();
  await expect(retention).toContainText("자동으로 지우지 않습니다");
  await expect(retention).toContainText("보관 기한도");
  // No screen in this product says a bare 검증됨, and none draws a sandbox badge.
  await expect(app.getByText("검증됨", { exact: true })).toHaveCount(0);
  await expect(app.locator(".badge", { hasText: "샌드박스" })).toHaveCount(0);
});

test("no listing response carries a path or the session credential", async ({ app, local }) => {
  await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));
  await expect(app.locator("[data-pack-row]")).toHaveCount(1);

  const listings = local.apiResponseBodies.filter((body) => body.includes("total_size_bytes"));
  expect(listings.length).toBeGreaterThan(0);
  for (const body of listings) {
    // A filesystem path cannot be written without a separator, and nothing
    // this body legitimately carries contains one.
    expect(body).not.toContain("/");
    expect(body).not.toContain("\\");
    expect(body).not.toContain(local.token);
    expect(body).not.toContain(local.root);
  }
});

test("the lifecycle screen is accessible empty and populated", async ({ app, local }) => {
  const errors = watchConsole(app);
  await open(app, local, PACKS_ROUTE(local.project_id));
  await expect(app.getByRole("heading", { level: 1, name: "내보낸 팩" })).toBeVisible();
  const empty = await axeSerious(app);
  expect(empty, JSON.stringify(empty, null, 2)).toEqual([]);

  for (let index = 0; index < 5; index += 1) await seedPack(app, local);
  await open(app, local, PACKS_ROUTE(local.project_id));
  await expect(app.locator("[data-pack-row]")).toHaveCount(5);
  const populated = await axeSerious(app);
  expect(populated, JSON.stringify(populated, null, 2)).toEqual([]);

  // Armed is a state axe has to be run against too: it is the only state in
  // which a destructive control is one press from acting.
  await app.locator('[data-action="delete-pack"]').first().click();
  const armed = await axeSerious(app);
  expect(armed, JSON.stringify(armed, null, 2)).toEqual([]);

  await expect(app.locator("h1")).toHaveCount(1);
  const overflow = await app.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
  expect(errors).toEqual([]);
  expect(local.fulfilledByHarness).toEqual([]);
});

test("the lifecycle screen is reachable from the project screen", async ({ app, local }) => {
  await seedPack(app, local);
  await open(app, local, `/projects/${local.project_id}`);

  await app.locator('[data-action="open-export-packs"]').focus();
  await app.keyboard.press("Enter");

  await expect(app.getByRole("heading", { level: 1, name: "내보낸 팩" })).toBeVisible();
  await expect(app.locator("[data-pack-row]")).toHaveCount(1);
});
