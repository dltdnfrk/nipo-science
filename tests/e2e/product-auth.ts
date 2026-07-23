import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname } from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import type { Page } from "@playwright/test";

const productPort = Number.parseInt(process.env.PRODUCT_UI_PORT ?? "18766", 10);
export const productOrigin = `http://127.0.0.1:${productPort}`;

export type ProductFixturePrincipal = "foreign" | "primary";

type ProductFixtureCredential = Readonly<{
  csrf: string;
  session: string;
}>;

class ProductFixtureCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProductFixtureCredentialError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCredential(value: unknown): ProductFixtureCredential {
  if (
    !isRecord(value) ||
    typeof value.csrf !== "string" ||
    !value.csrf ||
    typeof value.session !== "string" ||
    !value.session
  ) {
    throw new ProductFixtureCredentialError("Product fixture credential is invalid");
  }
  return { csrf: value.csrf, session: value.session };
}

function isPrivateMode(mode: number, expectedOwnerMode: number): boolean {
  return (mode & 0o777) === expectedOwnerMode;
}

function hasCurrentOwner(uid: number): boolean {
  return process.getuid === undefined || uid === process.getuid();
}

function isMissingFileError(value: unknown): boolean {
  return isRecord(value) && value.code === "ENOENT";
}

async function readCredentialDocument(path: string, directoryPath: string): Promise<unknown> {
  if (dirname(path) !== directoryPath) {
    throw new ProductFixtureCredentialError("Product fixture credential ancestry is invalid");
  }
  const directory = await lstat(directoryPath);
  if (!directory.isDirectory() || !isPrivateMode(directory.mode, 0o700) || !hasCurrentOwner(directory.uid)) {
    throw new ProductFixtureCredentialError("Product fixture credential directory is invalid");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const file = await handle.stat();
    if (!file.isFile() || !isPrivateMode(file.mode, 0o600) || !hasCurrentOwner(file.uid)) {
      throw new ProductFixtureCredentialError("Product fixture credential file is invalid");
    }
    return JSON.parse(await handle.readFile("utf-8"));
  } finally {
    await handle.close();
  }
}

async function waitForCredentialDocument(path: string, directoryPath: string): Promise<unknown> {
  const maxAttempts = 100;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      return await readCredentialDocument(path, directoryPath);
    } catch (error) {
      if (!isMissingFileError(error) || attempt === maxAttempts - 1) {
        throw error;
      }
      await delay(20);
    }
  }
  throw new ProductFixtureCredentialError("Product fixture credential publication timed out");
}

export async function productFixtureCredential(
  principal: ProductFixturePrincipal = "primary",
): Promise<ProductFixtureCredential> {
  const path = process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_FILE;
  const directoryPath = process.env.PRODUCT_UI_FIXTURE_CREDENTIALS_DIRECTORY;
  if (!path || !directoryPath) {
    throw new ProductFixtureCredentialError("Product fixture credential location is unavailable");
  }
  const decoded = await waitForCredentialDocument(path, directoryPath);
  if (!isRecord(decoded)) {
    throw new ProductFixtureCredentialError("Product fixture credential document is invalid");
  }
  return parseCredential(decoded[principal]);
}

export async function authenticateProduct(
  page: Page,
  principal: ProductFixturePrincipal = "primary",
): Promise<ProductFixtureCredential> {
  const credential = await productFixtureCredential(principal);
  const domain = new URL(productOrigin).hostname;
  await page.context().addCookies([
    {
      name: "product_session",
      value: credential.session,
      domain,
      path: "/",
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
    },
    {
      name: "product_csrf",
      value: credential.csrf,
      domain,
      path: "/",
      httpOnly: false,
      secure: false,
      sameSite: "Strict",
    },
  ]);
  return credential;
}
