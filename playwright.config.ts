/// <reference types="node" />

import process from "node:process";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { defineConfig } from "@playwright/test";

const port = Number.parseInt(process.env.ARTIFACT_UI_PORT ?? "18765", 10);
const baseURL = `http://127.0.0.1:${port}`;
const principalToken = process.env.ARTIFACT_UI_PRINCIPAL ?? "playwright-test-principal";
const productPort = Number.parseInt(process.env.PRODUCT_UI_PORT ?? "18766", 10);
const configuredCredentialsDirectory = process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_DIRECTORY;
const ownsCredentialsDirectory = configuredCredentialsDirectory === undefined;
const productCredentialsDirectory = configuredCredentialsDirectory
  ? resolve(configuredCredentialsDirectory)
  : mkdtempSync(join(tmpdir(), `science-workbench-product-ui-${productPort}-`));
if (ownsCredentialsDirectory) {
  chmodSync(productCredentialsDirectory, 0o700);
}
const productCredentialsFile = join(productCredentialsDirectory, "credentials.json");
const productCredentialsTempFile = join(productCredentialsDirectory, ".credentials.json.tmp");
const ownsCredentialsCleanup = process.env.PRODUCT_UI_FIXTURE_CLEANUP_OWNER_PID === undefined;
if (ownsCredentialsCleanup) {
  process.env.PRODUCT_UI_FIXTURE_CLEANUP_OWNER_PID = String(process.pid);
  process.once("exit", () => {
    rmSync(productCredentialsFile, { force: true });
    rmSync(productCredentialsTempFile, { force: true });
    if (ownsCredentialsDirectory) {
      rmSync(productCredentialsDirectory, { recursive: true, force: true });
    }
  });
}
process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_DIRECTORY = productCredentialsDirectory;
process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_FILE = productCredentialsFile;
process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_TEMP_FILE = productCredentialsTempFile;
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
const singleProcess = process.env.PLAYWRIGHT_SINGLE_PROCESS === "1";
const launchArgs = [
  "--disable-breakpad",
  "--disable-crash-reporter",
  ...(singleProcess ? ["--single-process", "--no-zygote"] : []),
];

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  projects: [
    { name: "mobile-375", use: { viewport: { width: 375, height: 812 } } },
    { name: "tablet-768", use: { viewport: { width: 768, height: 1024 } } },
    { name: "desktop-1280", use: { viewport: { width: 1280, height: 900 } } },
  ],
  use: {
    baseURL,
    browserName: "chromium",
    headless: true,
    storageState: {
      cookies: [{
        name: "artifact_test_principal",
        value: principalToken,
        domain: new URL(baseURL).hostname,
        path: "/",
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: "Strict",
      }],
      origins: [],
    },
    launchOptions: executablePath
      ? {
          executablePath,
          args: launchArgs,
        }
      : singleProcess
        ? { args: launchArgs }
        : undefined,
    screenshot: "only-on-failure",
    trace: "on",
    video: "retain-on-failure",
  },
  webServer: [
    {
      command: ".venv/bin/python -m tools.run_artifact_ui_fixture",
      env: {
        ARTIFACT_UI_PORT: String(port),
        ARTIFACT_UI_PRINCIPAL: principalToken,
        PYTHONDONTWRITEBYTECODE: "1",
      },
      reuseExistingServer: false,
      timeout: 15_000,
      url: `${baseURL}/artifacts`,
    },
    {
      command: ".venv/bin/python -m tools.run_product_ui_fixture",
      env: {
        PRODUCT_UI_PORT: String(productPort),
        PRODUCT_UI_FIXTURE_CREDENTIALS_DIRECTORY: productCredentialsDirectory,
        PRODUCT_UI_FIXTURE_CREDENTIALS_FILE: productCredentialsFile,
        PRODUCT_UI_FIXTURE_CREDENTIALS_TEMP_FILE: productCredentialsTempFile,
        PRODUCT_UI_FIXTURE_REMOVE_CREDENTIALS_DIRECTORY: ownsCredentialsDirectory ? "1" : "0",
        PYTHONPATH: `${process.cwd()}/packages/science:${process.cwd()}`,
        PYTHONDONTWRITEBYTECODE: "1",
      },
      reuseExistingServer: false,
      timeout: 15_000,
      url: `http://127.0.0.1:${productPort}/workspace`,
    },
  ],
});
