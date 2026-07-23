import type { Page } from "@playwright/test";
import { productOrigin } from "./product-auth.js";

export type ProviderAdapter = Readonly<{
  availability_label: string;
  connectable: boolean;
  default: boolean;
  disabled_reason: string | null;
  id: string;
  name: string;
  required: boolean;
}>;

export const providerLifecycleAdapters = [
  {
    id: "openai_codex",
    name: "OpenAI Codex",
    availability_label: "연결 가능",
    required: true,
    default: true,
    connectable: true,
    disabled_reason: null,
  },
  {
    id: "zai_glm",
    name: "Z.ai GLM",
    availability_label: "GLM 비활성화",
    required: false,
    default: false,
    connectable: false,
    disabled_reason: "unsupported_auth",
  },
] satisfies readonly ProviderAdapter[];

export const providerRenderingAdapters = [
  {
    id: "openai_codex",
    name: "OpenAI <img data-provider-injection src=x>",
    availability_label: "OpenAI 서버 비활성",
    required: true,
    default: true,
    connectable: false,
    disabled_reason: "server_policy_openai_disabled",
  },
  {
    id: "zai_glm",
    name: "Z.ai GLM",
    availability_label: "GLM 서버 연결 가능",
    required: false,
    default: false,
    connectable: true,
    disabled_reason: null,
  },
] satisfies readonly ProviderAdapter[];

export async function routeProviderRegistry(
  page: Page,
  payload: unknown = { adapters: providerLifecycleAdapters },
): Promise<void> {
  await page.route(`${productOrigin}/api/v1/provider-connections/registry`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(payload),
    }));
}
