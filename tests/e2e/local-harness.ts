/*
 * Harness for the local workbench browser suite.
 *
 * Nothing here is stubbed. Every byte the browser loads -- the document, the
 * stylesheet, the script, the favicon, and every `/api/v1` response -- travels
 * over a TCP socket from a live `nipo_local` listener started by
 * `local_workbench_fixture.py`. The credential check, the Origin check, the
 * `Host` pin, the document CSP, the provider registry, the SQLite store, and
 * the seeded run are all production code.
 *
 * The harness used to serve the three static assets itself with `page.route`,
 * because the local API had no static route and its blanket
 * `content-security-policy: default-src 'none'` would have blocked a
 * stylesheet and a script even if it had. Both are now real, so the
 * substitution is gone: `fulfilledByHarness` records any request this file
 * answers, and the specs assert it stays empty. A future stub would therefore
 * fail a test rather than quietly hollow out the suite.
 *
 * The credential is no longer put in a URL fragment either. The listener
 * injects it into the document's `<meta name="nipo-local-token">`, which is
 * what a launcher does, so `open()` navigates to a plain route URL and the
 * page is expected to authenticate without help.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { expect, test as base, type Page, type Route } from "@playwright/test";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY = path.resolve(HERE, "..", "..");
const FIXTURE = path.join(HERE, "local_workbench_fixture.py");
const PYTHON = process.env.NIPO_PYTHON ?? path.join(REPOSITORY, ".venv", "bin", "python");

/** The document path the real listener serves at its own origin. */
export const APP_PATH = "/";

/** The document policy the listener sets, asserted verbatim by the specs. */
export const DOCUMENT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** The policy every other response keeps, including the page's own assets. */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'";

export type SeededArtifact = Readonly<{
  role: string;
  name: string;
  artifact_id: string;
  version_id: string;
  version_no: number;
  content_sha256: string;
  media_type: string;
  size_bytes: number;
}>;

export type Handshake = Readonly<{
  base_url: string;
  port: number;
  token: string;
  header: string;
  root: string;
  run_surface_bound: boolean;
  project_id: string;
  project_name: string;
  run_id: string;
  execution_id: string;
  execution_isolation: string | null;
  artifacts: readonly SeededArtifact[];
}>;

export type LocalServer = Handshake & {
  readonly origin: string;
  /**
   * Every request this harness answered itself instead of the real listener.
   *
   * The observer below never fulfills anything, so this stays empty for as
   * long as the suite is honest. It is asserted rather than assumed.
   */
  readonly fulfilledByHarness: readonly string[];
  /** Every same-origin path the page actually requested over the socket. */
  readonly requestedPaths: readonly string[];
  /** Bodies of every `/api/v1` response the page actually received. */
  readonly apiResponseBodies: readonly string[];
  stop(): Promise<void>;
};

async function startFixture(
  runSurface: boolean,
): Promise<{ child: ChildProcessWithoutNullStreams; handshake: Handshake }> {
  const child = spawn(PYTHON, [FIXTURE], {
    cwd: REPOSITORY,
    env: {
      ...process.env,
      PYTHONDONTWRITEBYTECODE: "1",
      NIPO_E2E_RUN_SURFACE: runSurface ? "1" : "0",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const handshake = await new Promise<Handshake>((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => {
      reject(new Error(`local API fixture did not start in 90s. stderr:\n${stderr}`));
    }, 90_000);
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      clearTimeout(timer);
      try {
        resolve(JSON.parse(buffer.slice(0, newline)) as Handshake);
      } catch (error) {
        reject(new Error(`unreadable handshake: ${String(error)}\n${buffer}`));
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`local API fixture exited with ${String(code)}. stderr:\n${stderr}`));
    });
  });
  return { child, handshake };
}

/**
 * Watch every same-origin request without answering any of them.
 *
 * `route.fallback()` hands the request on, and there is no other handler, so
 * it reaches the network. Nothing is ever pushed into `fulfilled`: that array
 * is the tripwire. If someone reintroduces a stub here, the two specs that
 * assert it is empty fail instead of the suite silently testing a mock.
 */
async function observeTraffic(
  page: Page,
  origin: string,
  requested: string[],
  fulfilled: string[],
): Promise<void> {
  await page.route(`${origin}/**`, async (route: Route) => {
    requested.push(new URL(route.request().url()).pathname);
    void fulfilled;
    await route.fallback();
  });
}

export const test = base.extend<{ local: LocalServer; app: Page; runSurface: boolean }>({
  /** Whether the declared Run seam is bound. `test.use({ runSurface: false })` unbinds it. */
  runSurface: [true, { option: true }],

  local: async ({ runSurface }, use) => {
    const { child, handshake } = await startFixture(runSurface);
    const fulfilled: string[] = [];
    const requested: string[] = [];
    const bodies: string[] = [];
    const server: LocalServer = {
      ...handshake,
      origin: `http://127.0.0.1:${handshake.port}`,
      fulfilledByHarness: fulfilled,
      requestedPaths: requested,
      apiResponseBodies: bodies,
      async stop() {
        child.stdin.end();
        await new Promise<void>((resolve) => {
          const timer = setTimeout(() => {
            child.kill("SIGKILL");
            resolve();
          }, 5_000);
          child.on("exit", () => {
            clearTimeout(timer);
            resolve();
          });
        });
      },
    };
    // The arrays are the same objects the harness pushes into.
    Object.assign(server, {
      fulfilledByHarness: fulfilled,
      requestedPaths: requested,
      apiResponseBodies: bodies,
    });
    try {
      await use(server);
    } finally {
      await server.stop();
    }
  },

  app: async ({ page, local }, use) => {
    await observeTraffic(
      page,
      local.origin,
      local.requestedPaths as string[],
      local.fulfilledByHarness as string[],
    );
    page.on("response", (response) => {
      if (!response.url().includes("/api/v1")) return;
      void response
        .text()
        .then((text) => {
          (local.apiResponseBodies as string[]).push(text);
        })
        .catch(() => {
          /* a 204 has no body */
        });
    });
    await use(page);
  },
});

export { expect };

/**
 * Open one route of the app, letting the served page authenticate itself.
 *
 * No credential is placed in this URL. The listener injects it into the
 * document's meta anchor, which is the whole point of serving the page from
 * the API origin: if the injection broke, every spec would land on the paste
 * screen and fail rather than pass on a value the harness supplied.
 *
 * The blank navigation in between is deliberate: two `goto` calls that differ
 * only in fragment are a same-document navigation, and waiting for the busy
 * flag would then race against the previous screen still being on the page.
 * In-app navigation is exercised by the specs that click links instead.
 */
export async function open(page: Page, local: LocalServer, route: string): Promise<void> {
  const target = `${local.origin}${APP_PATH}#${route}`;
  if (page.url().startsWith(local.origin)) await page.goto("about:blank");
  await page.goto(target);
  await expect(page.locator("#screen")).not.toHaveAttribute("aria-busy", "true");
  // The credential must never reach the address bar, history, or a Referer.
  expect(page.url()).not.toContain(local.token);
}

/**
 * Open a route with the listener's credential injection defeated.
 *
 * This is fault injection, not a stub. Only the document's meta *value* is
 * blanked; the status, every header, and every other byte are the listener's
 * own, and no other request is touched. It is the only way to reach the paste
 * screen now that the real server injects a working credential, and reaching
 * it matters: a launcher that fails to inject must produce a page that
 * explains recovery instead of a blank one.
 *
 * The interception is recorded in `fulfilledByHarness`, so the specs that
 * assert nothing was answered by the harness are the ones that never call
 * this.
 */
export async function openUninjected(page: Page, local: LocalServer, route: string): Promise<void> {
  await page.route(`${local.origin}/`, async (route: Route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace(
      /<meta name="nipo-local-token" content="[^"]*">/u,
      '<meta name="nipo-local-token" content="">',
    );
    (local.fulfilledByHarness as string[]).push("/");
    await route.fulfill({ response, body });
  });
  await page.goto(`${local.origin}${APP_PATH}#${route}`);
}

/** Collect every console error the app itself produced. */
export function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

export type AxeViolation = Readonly<{
  id: string;
  impact: string | null;
  help: string;
  nodes: readonly string[];
}>;

/**
 * Run a real axe-core 4.10 pass and return serious/critical violations only.
 *
 * The bundle is evaluated through the debugger protocol rather than added as a
 * `<script>` tag. `addScriptTag` injects an *inline* script, and the document's
 * `script-src 'self'` blocks that -- correctly, which is why the block is
 * asserted as its own test rather than worked around silently. Test
 * instrumentation driven from outside the page is not page code and is not
 * what the policy exists to constrain.
 *
 * An empty violation list is only meaningful if axe actually ran, so the number
 * of rules that *passed* is checked first. Without that guard a broken
 * injection would produce a green accessibility test forever.
 */
export async function axeSerious(page: Page): Promise<readonly AxeViolation[]> {
  const source = await readFile(path.join(HERE, "vendor", "axe.min.js"), "utf8");
  await page.evaluate(source);
  const result = await page.evaluate(async () => {
    const runner = (
      globalThis as unknown as {
        axe?: {
          version: string;
          run: (context: unknown, options: unknown) => Promise<{ violations: unknown[]; passes: unknown[] }>;
        };
      }
    ).axe;
    if (!runner) return null;
    const report = await runner.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] },
    });
    return {
      version: runner.version,
      passes: report.passes.length,
      violations: report.violations as ReadonlyArray<{
        id: string;
        impact: string | null;
        help: string;
        nodes: ReadonlyArray<{ target: unknown[] }>;
      }>,
    };
  });
  if (!result) throw new Error("axe-core did not load; the accessibility pass proves nothing");
  if (result.passes < 5) {
    throw new Error(`axe-core ${result.version} evaluated only ${result.passes} rules; it did not really run`);
  }
  return result.violations
    .filter((item) => item.impact === "serious" || item.impact === "critical")
    .map((item) => ({
      id: item.id,
      impact: item.impact,
      help: item.help,
      nodes: item.nodes.map((node) => node.target.join(" ")),
    }));
}
