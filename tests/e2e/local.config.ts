/// <reference types="node" />

/*
 * The local workbench suite runs its own listener.
 *
 * It deliberately does not reuse the repository's root config: that config
 * starts two product fixture servers this suite has nothing to do with, and it
 * pins a `baseURL` and a cookie for the multi-tenant product. The local API
 * binds an ephemeral loopback port chosen by the kernel, so every URL here is
 * derived at run time from the handshake the fixture prints.
 */

import process from "node:process";
import { defineConfig } from "@playwright/test";

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
const singleProcess = process.env.PLAYWRIGHT_SINGLE_PROCESS === "1";
const launchArgs = [
  "--disable-breakpad",
  "--disable-crash-reporter",
  ...(singleProcess ? ["--single-process", "--no-zygote"] : []),
];

export default defineConfig({
  testDir: ".",
  testMatch: /local-.*\.spec\.ts$/u,
  // A private artifact directory under the already-ignored `.cache/`. The
  // repository's root config writes to `test-results/` and wipes it at the
  // start of a run, so sharing that tree makes two concurrent runs delete each
  // other's traces mid-flight -- which surfaces as an unrelated ENOENT in
  // whichever run loses the race, not as the real failure.
  outputDir: "../../.cache/test-results-local",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 120_000,
  reporter: [["list"]],
  projects: [
    { name: "mobile-375", use: { viewport: { width: 375, height: 812 } } },
    { name: "tablet-768", use: { viewport: { width: 768, height: 1024 } } },
    { name: "desktop-1280", use: { viewport: { width: 1280, height: 900 } } },
  ],
  use: {
    browserName: "chromium",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    launchOptions: executablePath
      ? { executablePath, args: launchArgs }
      : singleProcess
        ? { args: launchArgs }
        : undefined,
  },
});
