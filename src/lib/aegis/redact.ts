// Secret redaction before any external model call (PRD §3 safety guarantee).
// Security hardening (audit run-1): unconditional fail-closed masking — the previous
// process-global SEEN cap (500 literals) failed open, permanently disabling redaction
// once crossed. Masking is now always applied; no cross-run bookkeeping.
import { collectSecretLiterals } from "./drivers/gitleaks"
import type { RepoFile } from "./types"

/** Mask a secret literal: keep prefix/suffix, redact the middle, preserve length info. */
export function maskSecret(value: string): string {
  if (value.length <= 8) return `${value.slice(0, 2)}…${value.slice(-1)} (${value.length} chars, redacted)`
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars, redacted)`
}

/** Redact every secret literal found by the gitleaks corpus inside a text blob. */
export function redactText(text: string, files: RepoFile[]): string {
  let out = text
  for (const secret of collectSecretLiterals(files)) {
    if (secret.length < 6) continue
    if (!out.includes(secret)) continue
    out = out.split(secret).join(maskSecret(secret))
  }
  // generic catch for URLs with embedded credentials
  out = out.replace(
    /(\w+:\/\/[^:\s/]+:)([^@\s/]{4,})@/g,
    (_m, p1: string) => `${p1}••••••@`,
  )
  return out
}
