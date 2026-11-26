// AEGIS core domain types — shared between engine, API and UI
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

export type ScanTool = "gitleaks" | "bandit" | "semgrep" | "pip-audit" | "cf-skill"

export type RunMode = "REPORT_ONLY" | "AUTO_FIX"

export type RunStatus =
  | "RESOLVING"
  | "CLONING"
  | "SCANNING"
  | "TRIAGING"
  | "REMEDIATING"
  | "REPORTING"
  | "COMPLETED"
  | "FAILED"

export type StageName = "RESOLVE" | "CLONE" | "SCAN" | "TRIAGE" | "REMEDIATE" | "VERIFY" | "REPORT"

export const PIPELINE_STAGES: StageName[] = [
  "RESOLVE",
  "CLONE",
  "SCAN",
  "TRIAGE",
  "REMEDIATE",
  "VERIFY",
  "REPORT",
]

export type FindingStatus =
  | "DETECTED"
  | "TRIAGED"
  | "SUPPRESSED"
  | "PATCHING"
  | "VERIFIED"
  | "ESCALATED"
  | "FAILED"
  | "REPORTED"

export type VerifyResult =
  | "PASSED"
  | "FAILED_APPLY"
  | "FAILED_TESTS"
  | "FAILED_SYNTAX"
  | "FAILED_RESCAN"
  | "FAILED_POLICY"
  | "ABORTED_BUDGET"

export type EscalationReason =
  | "MAX_ATTEMPTS"
  | "BUDGET_EXHAUSTED"
  | "POLICY_PROTECTED_PATH"
  | "CRITICAL_SEVERITY"
  | "NO_SAFE_TEMPLATE"

export interface RepoFile {
  path: string
  content: string
  lines: string[]
}

// Normalized output of the scanner harness (one finding schema for all drivers)
export interface RawFinding {
  tool: ScanTool
  ruleId: string
  category: string
  severity: Severity
  title: string
  description: string
  filePath: string
  line: number
  endLine?: number
  evidence: string
  cve?: string
  fixHint?: string
}

export interface TriageDecision {
  refId: string
  severity: Severity
  suppress: boolean
  reasoning: string
  confidence: number
  categoryNote?: string
}

export interface StructuredEdit {
  filePath: string
  oldCode: string
  newCode: string
}

export interface PatchDraft {
  edits: StructuredEdit[]
  rationale: string
  riskNotes?: string
  strategy: "LLM_SINGLE" | "LLM_RETRY" | "TEMPLATE_FALLBACK"
}

export interface LlmUsage {
  promptTokens: number
  completionTokens: number
  latencyMs: number
}

export interface LlmResult<T> {
  ok: boolean
  data?: T
  usage: LlmUsage
  error?: string
  provider: "GROQ" | "ZAI" | "FALLBACK_HEURISTIC"
  model: string
  degraded: boolean // true when the fallback engine served the call
}

export interface RunBudgets {
  maxAttemptsPerFinding: number // PRD: 3
  costCeilingUsd: number
  wallClockCeilingMin: number // PRD target: < 15 min time-to-report
}

export const DEFAULT_BUDGETS: RunBudgets = {
  maxAttemptsPerFinding: 3,
  costCeilingUsd: 0.75,
  wallClockCeilingMin: 15,
}

export interface EngineSettings {
  groqApiKey: string
  groqModel: string
  budgets: RunBudgets
  protectedPaths: string[]
}

export const DEFAULT_PROTECTED_PATHS = ["**/auth.py", "**/auth/**", "**/migrations/**", "**/admin/**"]

export interface StageTelemetry {
  stage: StageName
  startedAt: number
  durationMs: number
  costUsd: number
}

export interface EventPayload {
  [key: string]: unknown
}
