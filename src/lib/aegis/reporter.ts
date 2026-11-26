// Reporter & Escalation — Markdown/HTML reports and the single pull-request payload
import type { MergedFinding } from "./dedup"
import type { RepoFile, RunMode, Severity } from "./types"

export interface AttemptRecord {
  attemptNo: number
  result: string
  strategy: string
  failureContext?: string | null
  rationale: string
  gates: { name: string; passed: boolean; detail: string }[]
}

export interface FindingRecord {
  refId: string
  tool: string
  tools: string[]
  ruleId: string
  category: string
  severity: Severity
  severityInitial: Severity
  title: string
  description: string
  filePath: string
  line: number
  evidence: string
  cve?: string | null
  reasoning?: string | null
  confidence?: number | null
  /** scanner's recommended fix — the report renders it whenever no verified patch exists */
  fixHint?: string | null
  suppressed: boolean
  status: string
  escalationReason?: string | null
  attempts: AttemptRecord[]
  finalPatch?: { edits: { filePath: string; oldCode: string; newCode: string }[]; rationale: string; riskNotes?: string } | null
}

/** Six-phase source-audit chapter payload (vendored Cloudflare security-audit-skill). */
export interface SkillAuditChapter {
  ok: boolean
  stats: { candidates: number; confirmed: number; needsValidation: number; rejected: number }
  ledgerStats: { total: number; covered: number; candidate: number; outOfScope: number }
  validators: { tool: string; pass: boolean; output: string }[]
  outputDir: string
}

export interface ReportInput {
  repoName: string
  repoUrl: string
  commitSha: string
  mode: RunMode
  engineMode: string
  model: string
  durationMs: number
  costUsd: number
  filesScanned: number
  locScanned: number
  coverage: { tool: string; role: string; filesScanned: number; findings: number }[]
  findings: FindingRecord[]
  budgets: { maxAttemptsPerFinding: number; costCeilingUsd: number; wallClockCeilingMin: number }
  /** Per-rule suppression drift across the findings store (PRD section 4 FP tracking). */
  fpStats?: { ruleId: string; tool: string; total: number; suppressed: number; fpRate: number }[]
  /** What this scan did not cover — blind spots stay visible (PRD section 4). */
  blindSpots?: string[]
  /** Critical-severity notifications fired this run (pluggable notifier, default console + event log). */
  criticalAlerts?: number
  /** Deep source-audit chapter (vendored Cloudflare security-audit-skill, six phases). */
  skillAudit?: SkillAuditChapter | null
}

const SEV_EMOJI: Record<string, string> = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" }

export function buildMarkdownReport(input: ReportInput): string {
  const { findings } = input
  const counts = countBySeverity(findings)
  const eligible = findings.filter((f) => !f.suppressed)
  const verified = findings.filter((f) => f.status === "VERIFIED")
  const suppressed = findings.filter((f) => f.suppressed)
  const escalated = findings.filter((f) => f.escalationReason)
  const autoFixRate = eligible.length > 0 ? Math.round((verified.length / eligible.length) * 100) : 0
  const suppressionRate = findings.length > 0 ? Math.round((suppressed.length / findings.length) * 100) : 0

  const lines: string[] = []
  lines.push(`# AEGIS Security Report — ${input.repoName}`)
  lines.push("")
  lines.push(`| | |`)
  lines.push(`|---|---|`)
  lines.push(`| Repository | \`${input.repoUrl}\` |`)
  lines.push(`| Pinned commit | \`${input.commitSha}\` |`)
  lines.push(`| Mode | ${input.mode === "AUTO_FIX" ? "Auto-fix with verification" : "Report-only"} |`)
  const engineLabel =
    input.engineMode === "GROQ"
      ? `Groq (${input.model})`
      : input.engineMode === "ZAI"
        ? `Platform LLM bridge (${input.model})`
        : "Self-hosted heuristic engine (degraded)"
  lines.push(`| Engine | ${engineLabel} |`)
  lines.push(`| Scan surface | ${input.filesScanned} files · ${input.locScanned} LOC |`)
  lines.push(`| Time-to-report | ${(input.durationMs / 1000).toFixed(1)}s (budget ${input.budgets.wallClockCeilingMin} min) |`)
  lines.push(`| Cost | $${input.costUsd.toFixed(4)} of $${input.budgets.costCeilingUsd} ceiling |`)
  lines.push(`| Generated | ${new Date().toISOString()} |`)
  lines.push("")
  lines.push("## Executive summary")
  lines.push("")
  lines.push(
    `- **${findings.length} findings** detected: ${counts.CRITICAL} critical, ${counts.HIGH} high, ${counts.MEDIUM} medium, ${counts.LOW} low.`,
  )
  lines.push(`- **${suppressed.length} probable false positives suppressed** (${suppressionRate}% of detections), each with recorded reasoning and confidence.`)
  if (input.mode === "AUTO_FIX") {
    lines.push(`- **${verified.length} verified fixes** (auto-fix rate ${autoFixRate}% of eligible findings; target ≥ 40%).`)
    lines.push(`- ${escalated.length} finding(s) escalated to the human review queue.`)
    lines.push(`- Every mutation passed the sandbox gate: apply → tests (repo pytest suite; py_compile fallback) → targeted re-scan → policy check.`)
  } else {
    lines.push("- Report-only mode: no mutations were attempted this run — every finding below carries evidence, location, severity and the scanner's recommended fix.")
  }
  lines.push(`- AEGIS never merges: fixes ship as a pull request; human review is the final gate.`)
  if ((input.criticalAlerts ?? 0) > 0) {
    lines.push(
      `- ${input.criticalAlerts} severity upgrade(s) to Critical fired immediate notifications (pluggable notifier; default console + run-log event).`,
    )
  }
  lines.push("")
  lines.push("## Severity model and response SLAs")
  lines.push("")
  lines.push("| Severity | Definition | Response | SLA |")
  lines.push("|---|---|---|---|")
  lines.push("| Critical | Actively exploitable or credential exposure | Immediate notification; fix priority 1; human review mandatory before merge | Same day |")
  lines.push("| High | Exploitable with preconditions, or severe bug | Fix priority 2 | 2 business days |")
  lines.push("| Medium | Defense-in-depth weakness or moderate bug | Fix priority 3 | 1 week |")
  lines.push("| Low | Hygiene and hardening | Backlog | Next cleanup |")
  lines.push("")
  lines.push("## Coverage per scanner")
  lines.push("")
  lines.push("| Tool | Role | Files | Findings |")
  lines.push("|---|---|---|---|")
  for (const c of input.coverage) {
    lines.push(`| ${c.tool} | ${c.role} | ${c.filesScanned} | ${c.findings} |`)
  }
  lines.push("")
  if (input.blindSpots && input.blindSpots.length > 0) {
    lines.push("## Blind spots (what this scan did not cover)")
    lines.push("")
    for (const b of input.blindSpots) lines.push(`- ${b}`)
    lines.push("")
  }
  lines.push("## Methodology")
  lines.push("")
  lines.push("1. **Resolve** — the repository is pinned to an exact commit before any analysis; every artifact below is reproducible against that ref.")
  lines.push("2. **Scan (deterministic ground truth)** — four rule engines (gitleaks, bandit, semgrep, pip-audit/OSV) plus the vendored Cloudflare security-audit-skill six-phase source audit (reconnaissance → coverage-ledger hunting → candidate validation → structured output gated by the vendored validators → independent record verification → target-neutral report). Cross-tool dedup merges corroborating detections.")
  lines.push("3. **Triage** — an LLM classifies final severity and suppresses only clearly-justified false positives; every decision is recorded with reasoning and confidence. Detection ground truth always belongs to the deterministic scanners.")
  lines.push("4. **Remediate + verify** — each patch is drafted, then applied in an isolated sandbox that re-compiles, re-scans and enforces policy gates; only sandbox-verified patches are staged for review.")
  lines.push("5. **Report** — this document; fixes ship as a pull request. AEGIS never merges.")
  lines.push("")
  // ---- deep source-audit chapter: the vendored Cloudflare security-audit-skill run
  if (input.skillAudit) {
    const s = input.skillAudit
    lines.push("## Deep source audit — vendored Cloudflare security-audit-skill")
    lines.push("")
    lines.push("Six-phase workflow executed inside this run against the pinned snapshot:")
    lines.push("")
    lines.push("| Phase | Stage | Outcome |")
    lines.push("|---|---|---|")
    lines.push(`| 1 | Reconnaissance | architecture mapped, trust boundaries recorded, out-of-scope surfaces excluded |`)
    lines.push(`| 2 | Coverage-led hunting | ${s.ledgerStats.total} ledger units assigned — ${s.stats.candidates} candidate(s) raised |`)
    lines.push(`| 3 | Candidate validation | ${s.stats.confirmed} confirmed · ${s.stats.needsValidation} needs-validation · ${s.stats.rejected} rejected |`)
    lines.push(`| 4 | Structured output | findings.json + coverage-ledger.json gated by the vendored Cloudflare validators (${s.validators.map((v) => `${v.tool} ${v.pass ? "PASS" : "FAIL"}`).join(", ")}) |`)
    lines.push(`| 5 | Independent record verification | fresh reviewers re-derived every record from source |`)
    lines.push(`| 6 | Target-neutral report | REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md emitted |`)
    lines.push("")
    lines.push("Coverage ledger:")
    lines.push("")
    lines.push("| Total units | Covered | Candidate | Out of scope / n/a |")
    lines.push("|---|---|---|---|")
    lines.push(`| ${s.ledgerStats.total} | ${s.ledgerStats.covered} | ${s.ledgerStats.candidate} | ${s.ledgerStats.outOfScope} |`)
    lines.push("")
    if (s.ok) {
      lines.push(
        `Confirmed skill records flow into the unified finding pipeline as tool \`cf-skill\` and pass through triage, remediation and reporting exactly like driver findings. Artifacts: \`${s.outputDir}/\`.`,
      )
    } else {
      lines.push(
        `_The skill run did not complete cleanly this run — driver findings remain authoritative. Artifacts (if written): \`${s.outputDir}/\`._`,
      )
    }
    lines.push("")
  }
  if (findings.length === 0) {
    lines.push("No findings detected. Coverage is reported per scan so blind spots stay visible.")
  }
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]) {
    const bucket = findings.filter((f) => f.severity === sev && !f.suppressed)
    if (bucket.length === 0) continue
    lines.push(`## ${sev} findings (${bucket.length})`)
    lines.push("")
    for (const f of bucket) {
      lines.push(`### ${f.refId} · ${f.title}`)
      lines.push("")
      lines.push(
        `- **Location**: \`${f.filePath}:${f.line}\` · **Tools**: ${f.tools.join(" + ")} · **Rule**: ${f.ruleId}${f.cve ? ` (${f.cve})` : ""}`,
      )
      if (f.severity !== f.severityInitial) {
        lines.push(`- **Severity**: ${f.severityInitial} → **${f.severity}** (adjusted by triage)`)
      }
      lines.push(`- **Description**: ${f.description}`)
      lines.push("- **Triage**: " + (f.reasoning ?? "n/a") + (f.confidence != null ? ` _(confidence ${f.confidence.toFixed(2)})_` : ""))
      if (f.fixHint && !f.finalPatch) {
        // no verified patch attached (report-only mode, escalated, or failed attempts) —
        // the scanner's recommended fix becomes the remediation guidance for the reader
        lines.push(`- **Recommended fix**: ${f.fixHint}`)
      }
      lines.push("")
      lines.push("```python")
      lines.push(f.evidence)
      lines.push("```")
      if (f.attempts.length > 0) {
        lines.push("")
        lines.push("| Attempt | Strategy | Result | Detail |")
        lines.push("|---|---|---|---|")
        for (const a of f.attempts) {
          lines.push(`| ${a.attemptNo} | ${a.strategy} | ${a.result} | ${escapeMd(a.failureContext ?? a.rationale).slice(0, 200)} |`)
        }
      }
      if (f.finalPatch) {
        lines.push("")
        lines.push("**Verified patch**")
        lines.push("")
        lines.push("```diff")
        for (const e of f.finalPatch.edits) {
          lines.push(`--- ${e.filePath}`)
          lines.push(`- ${e.oldCode.split("\n").join("\n- ")}`)
          lines.push(`+ ${e.newCode.split("\n").join("\n+ ")}`)
        }
        lines.push("```")
        lines.push("")
        lines.push(`> ${f.finalPatch.rationale}${f.finalPatch.riskNotes ? ` Risk: ${f.finalPatch.riskNotes}` : ""}`)
      }
      if (f.escalationReason) {
        lines.push("")
        lines.push(`> **Escalated (${f.escalationReason})** — full attempt history attached in the review queue.`)
      }
      lines.push("")
    }
  }
  if (suppressed.length > 0) {
    lines.push(`## Suppressed as probable false positives (${suppressed.length})`)
    lines.push("")
    lines.push("| Ref | Finding | Confidence | Reasoning |")
    lines.push("|---|---|---|---|")
    for (const f of suppressed) {
      lines.push(`| ${f.refId} | ${f.title} | ${(f.confidence ?? 0).toFixed(2)} | ${escapeMd(f.reasoning ?? "").slice(0, 160)} |`)
    }
    lines.push("")
    lines.push("_Weekly audit samples 5% of suppressions; per-rule FP drift is tracked._")
    lines.push("")
  }
  if ((input.fpStats?.length ?? 0) > 0) {
    lines.push("## False-positive tracking (per rule)")
    lines.push("")
    lines.push("| Rule | Tool | Detections | Suppressed | FP rate | Status |")
    lines.push("|---|---|---|---|---|---|")
    for (const s of input.fpStats ?? []) {
      const flagged = s.fpRate > 30
      lines.push(
        `| ${s.ruleId} | ${s.tool} | ${s.total} | ${s.suppressed} | ${s.fpRate.toFixed(1)}% | ${flagged ? "**ABOVE 30% — tune or disable**" : "nominal"} |`,
      )
    }
    lines.push("")
    lines.push(
      "_FP rate is tracked per rule and per tool across the findings store; any rule above 30% is tuned or disabled._",
    )
    lines.push("")
  }
  lines.push("## Appendix")
  lines.push("")
  lines.push("- Budgets: 3 attempts per finding, cost ceiling, wall-clock ceiling — checked before every attempt; runs always terminate.")
  lines.push("- Safety: secrets redacted before any external model call; repo token scoped read + PR creation; protected paths never auto-patched.")
  lines.push("- Notifications: Critical severity upgrades fire immediately via the pluggable notifier (default: console + run-log event).")
  lines.push("- Tests: patches run the repository's own pytest suite in the ephemeral sandbox; py_compile is the fallback when dependencies are unavailable offline.")
  lines.push("")
  lines.push("---")
  lines.push("_Generated by AEGIS v1.0 — deterministic tools set ground truth; the LLM drafts but never adjudicates._")
  return lines.join("\n")
}

export function buildPrPayload(input: ReportInput): { title: string; body: string } {
  const verified = input.findings.filter((f) => f.status === "VERIFIED")
  const criticalNeedsApproval = verified.filter((f) => f.severity === "CRITICAL")
  const lines: string[] = []
  lines.push(`AEGIS: ${verified.length} verified security fix${verified.length === 1 ? "" : "es"} for ${input.repoName}`)
  lines.push("")
  lines.push(
    `Automated remediation run at pinned commit \`${input.commitSha}\`. Every patch below passed the sandbox verification gate (tests → re-scan → policy). **AEGIS never merges — human review is the final gate.**`,
  )
  lines.push("")
  lines.push("## Verified fixes")
  for (const f of verified) {
    lines.push("")
    lines.push(`### ${f.refId} · ${f.title} (${f.severity})`)
    lines.push(`- Location: \`${f.filePath}:${f.line}\` · detected by ${f.tools.join(" + ")}`)
    lines.push(`- Rationale: ${f.finalPatch?.rationale ?? "n/a"}`)
    if (f.finalPatch?.riskNotes) lines.push(`- Residual risk: ${f.finalPatch.riskNotes}`)
    lines.push("")
    lines.push("```diff")
    for (const e of f.finalPatch?.edits ?? []) {
      lines.push(`- ${e.oldCode.split("\n").join("\n- ")}`)
      lines.push(`+ ${e.newCode.split("\n").join("\n+ ")}`)
    }
    lines.push("```")
  }
  if (criticalNeedsApproval.length > 0) {
    lines.push("")
    lines.push("## Requires explicit human approval (Critical)")
    for (const f of criticalNeedsApproval) lines.push(`- ${f.refId} ${f.title} — \`${f.filePath}:${f.line}\``)
  }
  lines.push("")
  lines.push("---")
  lines.push(
    "_Branch protection: AEGIS pushes to a remediation branch only. Escalated findings (budget exhaustion, protected paths, no safe template) are tracked in the review queue with full attempt history._",
  )
  return { title: `AEGIS security fixes (${verified.length} verified)`, body: lines.join("\n") }
}

function escapeMd(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ")
}

function countBySeverity(findings: FindingRecord[]): Record<string, number> {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) if (!f.suppressed) counts[f.severity] = (counts[f.severity] ?? 0) + 1
  return counts
}

export function buildHtmlReport(input: ReportInput): string {
  const md = buildMarkdownReport(input)
  const lines = md.split("\n")
  const out: string[] = []
  // Security hardening (audit run-2): fenced code blocks are rendered as *closed*
  // <pre> blocks with fully escaped content (previously the fence emitted an
  // unclosed <pre> and the code lines fell through to <p> handling), markdown
  // tables are no longer silently dropped from the HTML export, and the
  // document title is escaped — every byte of scanned-repo content that reaches
  // this same-origin document is neutralized.
  let inCode = false
  let codeBuf: string[] = []
  let tableBuf: string[] = []

  const flushCode = () => {
    if (codeBuf.length > 0) out.push(`<pre class="code">${codeBuf.join("\n")}</pre>`)
    codeBuf = []
  }
  const flushTable = () => {
    if (tableBuf.length === 0) return
    const rows = tableBuf
      .filter((r) => !/^\|[\s:|-]*\|?$/.test(r.trim()))
      .map((r) =>
        r
          .replace(/^\|/, "")
          .replace(/\|$/, "")
          .split("|")
          .map((c) => `<td>${mdInline(c.trim())}</td>`),
      )
    if (rows.length > 0) out.push(`<table>${rows.map((r) => `<tr>${r.join("")}</tr>`).join("")}</table>`)
    tableBuf = []
  }

  for (const line of lines) {
    if (line.startsWith("```")) {
      if (inCode) {
        flushCode()
        inCode = false
      } else {
        flushTable()
        inCode = true
      }
      continue
    }
    if (inCode) {
      codeBuf.push(escapeHtml(line))
      continue
    }
    if (/^\|/.test(line)) {
      tableBuf.push(line)
      continue
    }
    flushTable()
    if (line === "") continue
    if (line.startsWith("### ")) out.push(`<h3>${mdInline(line.slice(4))}</h3>`)
    else if (line.startsWith("## ")) out.push(`<h2>${mdInline(line.slice(3))}</h2>`)
    else if (line.startsWith("# ")) out.push(`<h1>${mdInline(line.slice(2))}</h1>`)
    else if (line === "---") out.push(`<hr/>`)
    else if (line.startsWith("- ")) out.push(`<li>${mdInline(line.slice(2))}</li>`)
    else if (line.startsWith("> ")) out.push(`<blockquote>${mdInline(line.slice(2))}</blockquote>`)
    else out.push(`<p>${mdInline(line)}</p>`)
  }
  flushTable()
  flushCode()
  const body = out.join("\n")
  return `<!doctype html><html><head><meta charset="utf-"/><title>AEGIS Report — ${escapeHtml(input.repoName)}</title>
<style>
body{font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;max-width:860px;margin:0 auto;padding:40px 24px;color:#0f172a;background:#fff;line-height:1.55}
h1{font-size:26px;border-bottom:2px solid #059669;padding-bottom:8px}
h2{font-size:19px;margin-top:36px;color:#065f46;border-bottom:1px solid #d1fae5;padding-bottom:4px}
h3{font-size:15px;margin-top:22px}
pre{background:#0b1220;color:#e2e8f0;padding:14px 16px;border-radius:10px;overflow:auto;font-size:12px;line-height:1.5}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
li{margin:4px 0}
hr{margin:32px 0;border:none;border-top:1px solid #e2e8f0}
blockquote{margin:12px 0;padding:8px 14px;border-left:3px solid #059669;background:#ecfdf5;border-radius:4px}
table{border-collapse:collapse;margin:16px 0;font-size:13px;width:100%}
td{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;vertical-align:top}
tr:nth-child(odd) td{background:#f8fafc}
</style></head><body>${body}</body></html>`
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

function mdInline(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/_([^_]+)_/g, "<em>$1</em>")
}
