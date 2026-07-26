/*
 * Honest disclosure and the credential boundary.
 *
 * Two things this repository has been burned by are asserted here directly:
 * a capability that is not implemented must not be drawn as an empty success,
 * and the local session credential must not leak into the address bar, browser
 * storage, or the rendered page.
 */

import {
  API_CSP,
  APP_PATH,
  DOCUMENT_CSP,
  axeSerious,
  expect,
  open,
  openUninjected,
  test,
  watchConsole,
} from "./local-harness.js";

test.describe("with the Run seam unbound, as a stock install ships", () => {
  test.use({ runSurface: false });

  test("the run list says the surface is missing instead of showing zero runs", async ({ app, local }) => {
    expect(local.run_surface_bound).toBe(false);
    await open(app, local, `/projects/${local.project_id}/runs`);

    await expect(app.locator('[data-state="run-surface-unavailable"]')).toBeVisible();
    await expect(app.getByText("실행 기록 표면이 연결되지 않았습니다")).toBeVisible();
    await expect(app.getByText("실행이 없다는 뜻이 아니라")).toBeVisible();

    // The two ways this could have lied: an empty-list message, or an error.
    await expect(app.getByText("이 프로젝트에는 실행이 없습니다")).toHaveCount(0);
    await expect(app.getByRole("alert")).toBeHidden();
  });

  test("a run detail route is equally honest", async ({ app, local }) => {
    await open(app, local, `/projects/${local.project_id}/runs/019f0000-0000-7000-8000-000000000001`);
    await expect(app.locator('[data-state="run-surface-unavailable"]')).toBeVisible();
  });

  test("the unavailable state is still accessible", async ({ app, local }) => {
    await open(app, local, `/projects/${local.project_id}/runs`);
    const violations = await axeSerious(app);
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
  });

  test("provenance discloses that isolation was never recorded", async ({ app, local }) => {
    // With no Run surface bound the API cannot answer for the producing
    // execution, so `execution_isolation` comes back null. The UI must say the
    // value is missing rather than assume a level.
    const csv = local.artifacts.find((item) => item.role === "csv");
    if (!csv) throw new Error("the fixture did not seed a csv output");
    await open(
      app,
      local,
      `/projects/${local.project_id}/artifacts/${csv.artifact_id}/versions/${csv.version_id}`,
    );
    const panel = app.locator(`[data-provenance="${csv.version_id}"]`);
    await expect(panel.locator('[data-isolation="unrecorded"]')).toBeVisible();
    await expect(panel).toContainText("격리 수준이 기록되지 않았습니다");
    await expect(panel).toContainText("격리되었다고 가정하지 마십시오");
    await expect(panel.locator('[data-isolation="in_process"]')).toHaveCount(0);
  });
});

test("with no credential the app explains recovery instead of failing blank", async ({ app, local }) => {
  const errors = watchConsole(app);
  // The listener injects a working credential, so the only way to reach this
  // screen is to defeat that injection -- which is exactly the launcher
  // failure the screen exists for.
  await openUninjected(app, local, "/settings/models");

  await expect(app.getByRole("heading", { level: 1, name: "로컬 서버에 연결해야 합니다" })).toBeVisible();
  await expect(app.getByText("api-token.json")).toBeVisible();
  await expect(app.getByLabel("로컬 세션 토큰")).toHaveAttribute("type", "password");
  // No provider data can have been fetched without the credential.
  await expect(app.locator(".provider-card")).toHaveCount(0);
  expect(errors).toEqual([]);

  const violations = await axeSerious(app);
  expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
});

test("the bootstrap screen connects with the keyboard alone and then scrubs the field", async ({ app, local }) => {
  await openUninjected(app, local, "/settings/models");
  const field = app.getByLabel("로컬 세션 토큰");
  await field.focus();
  await app.keyboard.type(local.token);
  await app.keyboard.press("Tab");
  await app.keyboard.press("Enter");

  await expect(app.getByRole("heading", { level: 1, name: "모델 설정" })).toBeVisible();
  await expect(app.locator(".provider-card")).toHaveCount(13);
  // The credential is gone from the form and was never persisted.
  expect(
    await app.evaluate(() => ({
      filledInputs: [...document.querySelectorAll("input")]
        .map((input) => input.value)
        .filter((value) => value !== ""),
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ filledInputs: [], local: [], session: [] });
});

test("a wrong credential is reported as such and reveals nothing", async ({ app, local }) => {
  // With no injected credential the fragment is the fallback intake, so this
  // also proves the injected value is the one that wins when both exist: the
  // page only reaches the fragment because the meta anchor was blanked.
  await openUninjected(app, local, "token=not-the-real-token&r=/settings/models");
  await expect(app.getByRole("alert")).toContainText("로컬 세션 토큰이 올바르지 않습니다");
  await expect(app.locator(".provider-card")).toHaveCount(0);
});

test("the injected credential beats a fragment one, so a crafted link cannot swap it", async ({
  app,
  local,
}) => {
  // The document the listener served already carries the real credential. A
  // `#token=` in the address must not be able to displace it, or a link
  // someone else wrote would decide which credential this page presents.
  await app.goto(`${local.origin}${APP_PATH}#token=not-the-real-token&r=/settings/models`);
  await expect(app.getByRole("heading", { level: 1, name: "모델 설정" })).toBeVisible();
  await expect(app.locator(".provider-card")).toHaveCount(13);
  await expect(app.getByRole("alert")).toBeHidden();
});

test("the credential never survives in the URL, the DOM, or storage", async ({ app, local }) => {
  await open(app, local, "/settings/models");

  expect(app.url()).not.toContain(local.token);
  expect(await app.evaluate(() => location.hash)).toBe("#/settings/models");
  expect(await app.content()).not.toContain(local.token);
  expect(
    await app.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
      meta: document.querySelector('meta[name="nipo-local-token"]')?.getAttribute("content") ?? "",
    })),
  ).toEqual({ local: [], session: [], meta: "" });

  // Navigating within the app must not put it back either.
  await app.getByRole("link", { name: "워크스페이스" }).click();
  await expect(app.getByRole("heading", { level: 1, name: "프로젝트" })).toBeVisible();
  expect(app.url()).not.toContain(local.token);
});

test("the local guard rejects a rebound Host even with the right credential", async ({ app, local }) => {
  // DNS rebinding is the attack that defeats an Origin check on a loopback
  // server. The pin is server-side; this proves the browser-facing surface
  // really answers 403 rather than the guard being dead code behind the token.
  await open(app, local, "/settings/models");
  const refusal = await app.request.get(`${local.origin}/api/v1/providers`, {
    headers: { "X-Nipo-Token": local.token, Host: "workbench.attacker.example" },
  });
  expect(refusal.status()).toBe(403);
  expect(await refusal.text()).toContain("host_not_allowed");
});

test("the listener serves the page at its own origin under a document-only policy", async ({
  app,
  local,
}) => {
  // This was a recorded finding: the listener answered 404 for every path
  // outside /api/v1, so nothing served index.html and the harness had to.
  // Both halves are now real, and both are asserted -- the page is served,
  // and the policy that would have blocked its stylesheet and script applies
  // to the document alone.
  const page = await app.request.get(`${local.origin}/`);
  expect(page.status()).toBe(200);
  expect(page.headers()["content-type"]).toBe("text/html; charset=utf-8");
  expect(page.headers()["content-security-policy"]).toBe(DOCUMENT_CSP);
  // Every source in that policy is 'self'. Nothing inline, nothing remote.
  expect(page.headers()["content-security-policy"]).not.toContain("unsafe-inline");
  expect(page.headers()["content-security-policy"]).not.toContain("unsafe-eval");
  expect(page.headers()["content-security-policy"]).not.toContain("http");
  expect(page.headers()["x-content-type-options"]).toBe("nosniff");
  expect(page.headers()["referrer-policy"]).toBe("no-referrer");
  expect(page.headers()["x-frame-options"]).toBe("DENY");
  expect(page.headers()["access-control-allow-origin"]).toBeUndefined();

  // The two subresources the page needs are served, and they keep the
  // API-wide policy: only the document is served under a relaxed one.
  for (const asset of ["/app.js", "/styles.css"]) {
    const response = await app.request.get(`${local.origin}${asset}`);
    expect(response.status(), asset).toBe(200);
    expect(response.headers()["content-security-policy"], asset).toBe(API_CSP);
  }

  const health = await app.request.get(`${local.origin}/api/v1/health`, {
    headers: { "X-Nipo-Token": local.token },
  });
  expect(health.status()).toBe(200);
  // API responses are unchanged: nothing a browser loads from them may run.
  expect(health.headers()["content-security-policy"]).toBe(API_CSP);
});

test("the served document carries this run's credential and nothing else does", async ({
  app,
  local,
}) => {
  const page = await app.request.get(`${local.origin}/`);
  const body = await page.text();
  // The credential is delivered in the meta anchor, which never reaches a
  // URL, browser history, or a `Referer`.
  expect(body).toContain(`<meta name="nipo-local-token" content="${local.token}">`);

  // No other served byte carries it, and neither does an API response.
  for (const asset of ["/app.js", "/styles.css", "/favicon.svg"]) {
    const response = await app.request.get(`${local.origin}${asset}`);
    expect(await response.text(), asset).not.toContain(local.token);
  }
  const health = await app.request.get(`${local.origin}/api/v1/health`, {
    headers: { "X-Nipo-Token": local.token },
  });
  expect(await health.text()).not.toContain(local.token);
});

test("no request can reach a file outside the served set", async ({ app, local }) => {
  // Every served path is registered as a literal, so there is no path
  // parameter for a traversal sequence to act on. These are the shapes that
  // would exploit one if it existed.
  const attempts = [
    "/../etc/passwd",
    "/%2e%2e/etc/passwd",
    "/%2e%2e%2fetc%2fpasswd",
    "/..%2f..%2fetc%2fpasswd",
    "/./app.js/../../../etc/passwd",
    "/nipo.sqlite3",
    "/api-token.json",
    "/credentials.json",
  ];
  for (const attempt of attempts) {
    const response = await app.request.get(`${local.origin}${attempt}`, {
      headers: { "X-Nipo-Token": local.token },
    });
    expect(response.status(), attempt).toBe(404);
    expect(await response.text(), attempt).toContain("not_found");
  }
});

test("a cross-site load of the credential-bearing document is refused", async ({ app, local }) => {
  // The document cannot carry a custom header, so the guard enforces
  // Sec-Fetch-Site on it for every method rather than only state-changing
  // ones. That is what stops another site framing or scripting this page.
  for (const site of ["cross-site", "same-site"]) {
    const refusal = await app.request.get(`${local.origin}/`, {
      headers: { "Sec-Fetch-Site": site },
    });
    expect(refusal.status(), site).toBe(403);
    expect(await refusal.text(), site).toContain("cross_origin_denied");
  }
  // A user-initiated navigation and a same-origin subresource both pass.
  for (const site of ["none", "same-origin"]) {
    const allowed = await app.request.get(`${local.origin}/`, {
      headers: { "Sec-Fetch-Site": site },
    });
    expect(allowed.status(), site).toBe(200);
  }
  // The API surface still demands the credential; the document exemption is
  // a closed set of literal paths, not a hole in the guard.
  const denied = await app.request.get(`${local.origin}/api/v1/providers`);
  expect(denied.status()).toBe(401);
  expect(await denied.text()).toContain("local_token_required");
});

test("the page loads its own script and stylesheet under that policy", async ({ app, local }) => {
  // A policy that is correct in a header and wrong in a browser is worth
  // nothing, so this asserts the rendered result: no CSP violation, and the
  // stylesheet and script both actually applied.
  const errors = watchConsole(app);
  await open(app, local, "/settings/models");

  await expect(app.getByRole("heading", { level: 1, name: "모델 설정" })).toBeVisible();
  expect(errors.filter((line) => line.includes("Content Security Policy"))).toEqual([]);
  expect(errors).toEqual([]);
  // The stylesheet applied: the shell has its own background, not the default.
  expect(
    await app.evaluate(() => getComputedStyle(document.body).backgroundColor),
  ).not.toBe("rgba(0, 0, 0, 0)");
  // The page and both assets came from the listener over the socket.
  expect(local.requestedPaths).toContain("/");
  expect(local.requestedPaths).toContain("/app.js");
  expect(local.requestedPaths).toContain("/styles.css");
  expect(local.fulfilledByHarness).toEqual([]);
});

test("the browser really enforces the document policy, not just reports it", async ({
  app,
  local,
}) => {
  await open(app, local, "/settings/models");

  // An inline script is refused by the browser under `script-src 'self'`.
  // This is the outcome test for the policy: a header a browser ignored would
  // let this succeed.
  await expect(
    app.addScriptTag({ content: "globalThis.__nipoInline = true;" }),
  ).rejects.toThrow(/Content Security Policy/u);
  expect(await app.evaluate(() => "__nipoInline" in globalThis)).toBe(false);

  // A remote script is refused too: `'self'` is the only source, so no CDN.
  await expect(
    app.addScriptTag({ url: "https://cdn.example.com/anything.js" }),
  ).rejects.toThrow();
});
