/// <reference types="node" />

import process from "node:process";
import { defineConfig } from "@playwright/test";

const port = 18765;
const baseURL = `http://127.0.0.1:${port}`;
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
  webServer: {
    command: ".venv/bin/python -m tools.run_artifact_ui_fixture",
    env: {
      ARTIFACT_UI_PORT: String(port),
      ARTIFACT_UI_PRINCIPAL: "playwright-test-principal",
      PYTHONDONTWRITEBYTECODE: "1",
    },
    reuseExistingServer: false,
    timeout: 15_000,
    url: `${baseURL}/artifacts`,
  },
});
