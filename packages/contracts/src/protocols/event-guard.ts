import type { z } from "zod"

const monetaryEventStems = ["cost", "price", "spend", "budget", "monetary", "currency"]
const credentialNames =
  "authorization|token|credential|credentials|apikey|cookie|password|passwd|secret|privatekey|bearer".split(
    "|",
  )
const benignCredentialPrefixes = ["tokenization", "passwordless", "secretory", "secretome"]
const secretValuePatterns: readonly RegExp[] = [
  /^\s*(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{24,}\s*$/i,
  /^\s*(?:client[\s_-]*(?:secret|password)|api[\s_-]*(?:key|token|secret)|(?:access|refresh|auth)[\s_-]*token|secret|token|password|passwd)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{24,}["']?\s*$/i,
  /^\s*(?:(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|xox[baprs]-|[rs]k_live_|AIza|ya29\.)[A-Za-z0-9_-]{24,}|(?:AKIA|ASIA)[0-9A-Z]{16})\s*$/i,
  /^\s*-{5}BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-{5}/i,
]

const forbiddenEventKey = (key: string): boolean => {
  const normalized = key
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "")
  const monetary = monetaryEventStems.some((stem) => normalized.includes(stem))
  const prefix = credentialNames.some((name) => normalized.startsWith(name))
  const benignPrefix = benignCredentialPrefixes.some((name) => normalized.startsWith(name))
  const credential =
    credentialNames.some((name) => normalized.endsWith(name)) || (prefix && !benignPrefix)
  const fallback = normalized.includes("provider") && normalized.includes("fallback")
  return monetary || credential || fallback
}

const forbiddenEventValue = (value: string): boolean => {
  const normalized = value.normalize("NFKC")
  return secretValuePatterns.some((pattern) => pattern.test(normalized))
}

export const containsForbiddenEventData = (value: z.infer<typeof z.json>): boolean => {
  if (Array.isArray(value)) return value.some(containsForbiddenEventData)
  if (typeof value === "string") return forbiddenEventValue(value)
  if (value === null || typeof value !== "object") return false
  return Object.entries(value).some(
    ([key, item]) => forbiddenEventKey(key) || containsForbiddenEventData(item),
  )
}
