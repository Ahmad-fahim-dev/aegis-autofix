// Triage Engine — LLM-assisted dedup, classification, severity, false-positive suppression.
// The LLM never decides detection ground truth; every suppression is logged (PRD §3).
import type { MergedFinding } from "./dedup"
import type { RawFinding, ScanTool, Severity, TriageDecision } from "./types"
import { redactText } from "./redact"
import { llmRoute, estimateCostUsd } from "./groq"
import type { RepoFile } from "./types"

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

export interface TriageOutcome {
  decisions: TriageDecision[]
  provider: "GROQ" | "ZAI" | "FALLBACK_HEURISTIC"
  model: string
  degraded: boolean
  costUsd: number
  promptTokens: number
  completionTokens: number
  latencyMs: number
  error?: string
}

const SYSTEM = `You are the AEGIS Triage Engine for a static-security-analysis pipeline.
You receive findings already detected by deterministic scanners (Semgrep, Bandit, Gitleaks, pip-audit/OSV). You NEVER adjudicate whether a detection is real ground truth — you only:
1. classify each finding's final severity (CRITICAL | HIGH | MEDIUM | LOW),
2. suppress probable false positives (only when clearly justified),
3. record reasoning and a confidence score (0..1).
Severity definitions: CRITICAL = actively exploitable or credential exposure; HIGH = exploitable with preconditions or a severe bug; MEDIUM = defense-in-depth weakness or moderate bug; LOW = hygiene and hardening cleanup.
Suppress ONLY if the code context proves the pattern is safe or non-security (e.g. a weak hash used for a documented non-security checksum). When in doubt, do NOT suppress.
Respond with STRICT JSON only: {"decisions":[{"refId":"...","severity":"HIGH","suppress":false,"reasoning":"...","confidence":0.0}]}. Every received refId must appear exactly once.`

export async function triageFindings(
  merged: MergedFinding[],
  files: RepoFile[],
  opts: { apiKey: string; model: string },
): Promise<TriageOutcome> {
  const payload = merged.map((m) => ({
    refId: m.refId,
    tools: m.tools,
    ruleIds: m.ruleIds,
    category: m.primary.category,
    severity: m.primary.severity,
    title: m.primary.title,
    description: m.primary.description.slice(0, 240),
    filePath: m.primary.filePath,
    line: m.primary.line,
    evidence: m.primary.evidence.split("\n").slice(0, 6).join("\n"),
  }))
  const user = `Repository snapshot findings (${merged.length}). Redacted evidence may mask secret literals.\n\n${redactText(
    JSON.stringify({ findings: payload }),
    files,
  )}`

  const result = await llmRoute<TriageDecision[]>(
    {
      apiKey: opts.apiKey,
      model: opts.model,
      system: SYSTEM,
      user,
      maxTokens: 4000,
      timeoutMs: 60000,
    },
    validateDecisions(merged),
    () => ({
      data: heuristicTriage(merged),
      reasoning: "All LLM providers unavailable — deterministic heuristic triage applied (self-hosted model option).",
    }),
  )

  const decisions = result.data ?? heuristicTriage(merged)
  return {
    decisions,
    provider: result.provider,
    model: result.model,
    degraded: result.degraded,
    costUsd: estimateCostUsd(result.model, result.usage),
    promptTokens: result.usage.promptTokens,
    completionTokens: result.usage.completionTokens,
    latencyMs: result.usage.latencyMs,
    error: result.error,
  }
}

function validateDecisions(merged: MergedFinding[]) {
  return (parsed: unknown): TriageDecision[] | null => {
    const root = parsed as { decisions?: unknown }
    if (!root || typeof root !== "object" || !Array.isArray(root.decisions)) return null
    const out: TriageDecision[] = []
    const byId = new Map(merged.map((m) => [m.refId, m]))
    const seen = new Set<string>()
    for (const d of root.decisions as Record<string, unknown>[]) {
      const refId = String(d.refId ?? "")
      if (!byId.has(refId) || seen.has(refId)) return null
      const sev = String(d.severity ?? "") as Severity
      if (!["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sev)) return null
      const suppress = typeof d.suppress === "boolean" ? d.suppress : null
      if (suppress === null) return null
      const reasoning = String(d.reasoning ?? "")
      if (reasoning.length < 15) return null
      const confidence = Number(d.confidence)
      if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) return null
      seen.add(refId)
      out.push({ refId, severity: sev, suppress, reasoning, confidence })
    }
    if (out.length !== merged.length) return null
    return out
  }
}

/** Deterministic self-hosted fallback triage: reasoning and confidence are always recorded. */
export function heuristicTriage(merged: MergedFinding[]): TriageDecision[] {
  return merged.map((m) => {
    const f = m.primary
    const corroborated = m.tools.length
    const base = 0.72 + Math.min(0.18, (corroborated - 1) * 0.09)

    // documented false-positive pattern: weak hash used for a non-security checksum
    const isWeakHash = f.ruleId === "B-324"
    const nonSecurityContext = /not security|non-?security|nonsecurity|checksum/i.test(f.evidence)
    if (isWeakHash && nonSecurityContext) {
      return {
        refId: m.refId,
        severity: "LOW",
        suppress: true,
        reasoning:
          "Suppressed as probable false positive: the MD5 use is a documented non-security checksum (docstring/comment marks it as non-cryptographic idempotency), so no exploitable weakness exists. Suppression sampled in the weekly audit.",
        confidence: 0.64,
        categoryNote: "FP-suppression candidate — flagged for the weekly 5% audit sample.",
      }
    }

    let severity = f.severity
    // deterministic adjustments mirroring the LLM policy
    if (f.category === "hardcoded-secret" && f.ruleId === "GL-007" && /example|placeholder|changeme|xxx/i.test(f.evidence)) {
      severity = "MEDIUM"
    }

    const rationale = [
      `${corroborated > 1 ? `Corroborated by ${corroborated} independent tools (${m.tools.join(", ")}); ` : ""}rule ${f.ruleId} (${f.category}) from ${f.tool}.`,
      f.cve ? `Dependency advisory ${f.cve} with a fixed version available.` : f.description.split(".")[0] + ".",
      `Scanner default severity ${f.severity} retained${severity !== f.severity ? `→ adjusted to ${severity}` : ""}.`,
    ].join(" ")

    return {
      refId: m.refId,
      severity,
      suppress: false,
      reasoning: rationale,
      confidence: Math.min(0.95, base),
    }
  })
}
