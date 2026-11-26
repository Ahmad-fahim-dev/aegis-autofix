// AEGIS orchestrator — Scan -> Triage -> Remediate -> Verify -> Report
// Event-sourced run log: every scan, prompt, response, patch and test result is recorded.
import { randomUUID } from "crypto"
import path from "path"
import { db } from "@/lib/db"
import { scanRepo } from "./drivers"
import { dedupFindings, type MergedFinding } from "./dedup"
import { triageFindings } from "./triage"
import { draftPatchLlm, templatePatch } from "./remediate"
import { sandboxVerify, type SandboxGate } from "./sandbox"
import { addCost, budgetCheck, initBudgetState, isProtectedPath } from "./policy"
import { buildHtmlReport, buildMarkdownReport, buildPrPayload, type FindingRecord, type SkillAuditChapter } from "./reporter"
import { resolveRepo, loadRepoFiles, type ResolvedRepo } from "./repo"
import { maskSecret, redactText } from "./redact"
import { collectSecretLiterals } from "./drivers/gitleaks"
import { estimateCostUsd } from "./groq"
import { getNotifier } from "./notifier"
import { DEFAULT_BUDGETS, DEFAULT_PROTECTED_PATHS, type EngineSettings, type RawFinding, type RepoFile, type RunBudgets } from "./types"
import { runSkillAudit } from "./audit/runner"

const BROADCAST_URL = "http://127.0.0.1:3001/broadcast"

// Security hardening (audit run-1): run admission control — a bounded concurrency
// semaphore for background engine executions in this shared server process.
// POST /api/runs rejects with 429 when the engine is at capacity.
const MAX_ACTIVE_RUNS = 2
const ACTIVE_RUNS = new Set<string>()
export function activeRunCount(): number {
  return ACTIVE_RUNS.size
}
export const ENGINE_ADMISSION = { MAX_ACTIVE_RUNS }

export async function loadEngineSettings(): Promise<EngineSettings> {
  let override: { groqApiKey?: string; groqModel?: string; budgets?: RunBudgets; protectedPaths?: string[] } = {}
  try {
    const row = await db.setting.findUnique({ where: { key: "engine" } })
    if (row) override = JSON.parse(row.valueJson)
  } catch {
    /* defaults */
  }
  return {
    groqApiKey: override.groqApiKey || process.env.GROQ_API_KEY || "",
    groqModel: override.groqModel || process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
    budgets: { ...DEFAULT_BUDGETS, ...(override.budgets ?? {}) },
    protectedPaths: override.protectedPaths && override.protectedPaths.length > 0 ? override.protectedPaths : DEFAULT_PROTECTED_PATHS,
  }
}

// Stale-run reaper. A dev-server restart or crash mid-run used to leave rows in
// SCANNING/REMEDIATING/… forever: the console polled them indefinitely, stats
// counted them as active, and nothing ever closed them. Any live engine caps a
// run at the 15m wall-clock SLA, so a non-terminal row whose startedAt is 20+
// minutes old (and that THIS process is not actively executing) is provably
// orphaned — fail it with the stage attribution so the graph shows where it died.
const STALE_RUN_MS = 20 * 60_000
const SWEEP_INTERVAL_MS = 30_000
let lastSweepAt = 0
export async function sweepStaleRuns(): Promise<void> {
  const now = Date.now()
  if (now - lastSweepAt < SWEEP_INTERVAL_MS) return
  lastSweepAt = now
  try {
    const stale = await db.run.findMany({
      where: {
        status: { in: ["RESOLVING", "CLONING", "SCANNING", "TRIAGING", "REMEDIATING", "REPORTING"] },
        startedAt: { lt: new Date(now - STALE_RUN_MS) },
      },
      select: { id: true, status: true },
    })
    for (const r of stale) {
      if (ACTIVE_RUNS.has(r.id)) continue // this process owns it — still live
      await db.run.update({
        where: { id: r.id },
        data: {
          status: "FAILED",
          failedStage: graphStageIdx(r.status),
          error: "Run abandoned — engine process restarted or crashed before completion",
          finishedAt: new Date(),
        },
      })
      try {
        const last = await db.event.findFirst({ where: { runId: r.id }, orderBy: { seq: "desc" }, select: { seq: true } })
        await db.event.create({
          data: {
            runId: r.id,
            seq: (last?.seq ?? 0) + 1,
            type: "RUN_FAILED",
            stage: emitStageFor(r.status),
            level: "error",
            message: "Run abandoned — engine process restarted or crashed before completion",
            payloadJson: null,
          },
        })
      } catch {
        /* event log write is best-effort */
      }
    }
  } catch {
    /* sweep is best-effort — never break the read path */
  }
}

interface Emitter {
  (type: string, opts?: { stage?: string; level?: "info" | "success" | "warn" | "error"; message?: string; payload?: Record<string, unknown> }): Promise<void>
}

async function broadcast(runId: string, event: Record<string, unknown>) {
  try {
    // Security hardening (audit run-1): the /broadcast bridge is authenticated with a
    // server-to-server shared secret — unauthenticated peers can no longer forge events.
    const bridgeToken = process.env.AEGIS_BRIDGE_TOKEN
    if (!bridgeToken) return // fail closed when the bridge secret is unconfigured
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 1500)
    await fetch(BROADCAST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-bridge-token": bridgeToken },
      body: JSON.stringify({ runId, event }),
      signal: controller.signal,
    })
    clearTimeout(t)
  } catch {
    /* realtime service is optional — events remain in the store */
  }
}

export async function executeRun(runId: string): Promise<void> {
  const run = await db.run.findUnique({ where: { id: runId } })
  if (!run) return

  const settings = await loadEngineSettings()
  const budget = initBudgetState(settings.budgets)
  let seq = 0
  let files: RepoFile[] = []
  // last status written to the store — the failure path uses it to attribute the
  // failure to the correct pipeline stage instead of guessing
  let lastStatus = "RESOLVING"
  // Security hardening (audit run-1): hoisted so the clone is cleaned up on EVERY
  // outcome — the catch path previously skipped repo.cleanup(), retaining trees under /tmp.
  let repo: ResolvedRepo | undefined
  ACTIVE_RUNS.add(runId)

  const emit: Emitter = async (type, opts = {}) => {
    seq += 1
    const event = {
      id: `${Date.now()}-${seq}`,
      runId,
      seq,
      type,
      stage: opts.stage ?? null,
      level: opts.level ?? "info",
      message: opts.message ?? type,
      payload: opts.payload ?? null,
      ts: new Date().toISOString(),
    }
    try {
      await db.event.create({
        data: {
          runId,
          seq,
          type,
          stage: opts.stage ?? null,
          level: opts.level ?? "info",
          message: opts.message ?? null,
          payloadJson: opts.payload ? JSON.stringify(opts.payload) : null,
        },
      })
    } catch {
      /* keep going */
    }
    void broadcast(runId, event)
  }

  const setRun = async (data: Record<string, unknown>) => {
    // track the pipeline's live position so a failure can be attributed to the
    // stage it actually died in (persisted as Run.failedStage for the execution graph)
    if (typeof data.status === "string") lastStatus = data.status
    try {
      await db.run.update({ where: { id: runId }, data })
    } catch {
      /* keep going */
    }
  }

  // pluggable notifier — Critical severity upgrades fire immediately (console + run-log event by default)
  const notifier = getNotifier(emit)

  try {
    await emit("RUN_STARTED", { stage: "RESOLVE", level: "info", message: `Run started — target ${run.repoUrl}`, payload: { mode: run.mode } })

    // ---- RESOLVE + CLONE (pinned commit)
    await setRun({ status: "RESOLVING" })
    const resolved = await resolveRepo({ url: run.repoUrl })
    if (!resolved.ok || !resolved.repo) {
      await emit("REPO_RESOLVE_FAILED", {
        stage: "RESOLVE",
        level: "error",
        message: resolved.error ?? "repo resolution failed",
        payload: { guidance: resolved.guidance ?? "" },
      })
      await setRun({ status: "FAILED", failedStage: 0, error: resolved.error ?? "resolution failed", finishedAt: new Date() })
      return
    }
    repo = resolved.repo
    files = resolved.files
    const secretBindings: Record<string, string> = {}
    for (const secret of collectSecretLiterals(files)) secretBindings[maskSecret(secret)] = secret

    await emit("REPO_RESOLVED", {
      stage: "CLONE",
      level: "success",
      message: `${repo.repoName} resolved (${repo.source === "SAMPLE" ? "sample fixture" : "shallow clone"}), pinned @ ${repo.commitSha}`,
      payload: { source: repo.source, commitSha: repo.commitSha, files: files.length },
    })
    await setRun({ status: "CLONING", repoName: repo.repoName, repoSource: repo.source, commitSha: repo.commitSha })

    // ---- SCAN (deterministic ground truth + Cloudflare security-audit-skill)
    await setRun({ status: "SCANNING" })
    const scanStart = Date.now()
    await emit("STAGE_STARTED", { stage: "SCAN", message: "Scanner harness running 4 drivers (gitleaks, bandit, semgrep, pip-audit/OSV) + the vendored Cloudflare security-audit-skill six-phase audit" })
    const scan = scanRepo(files)
    await emit("SCAN_COMPLETE", {
      stage: "SCAN",
      level: "success",
      message: `${scan.findings.length} raw findings from ${scan.filesScanned} files (${scan.locScanned} LOC) in ${Date.now() - scanStart}ms`,
      payload: { raw: scan.findings.length, coverage: scan.coverage, filesScanned: scan.filesScanned, locScanned: scan.locScanned },
    })
    await setRun({ filesScanned: scan.filesScanned, locScanned: scan.locScanned })

    // ---- SCAN phase 2: Cloudflare security-audit-skill audit of the target repo.
    // The vendored skill (skills/security-audit) runs INSIDE this backend on every
    // audit run: reconnaissance -> coverage-led hunting -> candidate validation ->
    // structured output gated by the vendored validators -> independent record
    // verification -> target-neutral report. Confirmed records join the unified
    // finding pipeline (tool "cf-skill") and flow through triage/remediate/report
    // exactly like driver findings; the skill's artifacts land in .aegis-audit/<runId>.
    // The summary is hoisted so the REPORT phase can render a dedicated chapter
    // (coverage ledger stats, verdict counts, validator results, artifact paths).
    const skillFindings: RawFinding[] = []
    let skillSummary: SkillAuditChapter | null = null
    try {
      const skillAudit = await runSkillAudit(files, { repoName: repo.repoName, sourceRef: repo.commitSha, runId })
      for (const ev of skillAudit.events) {
        await emit(ev.type, {
          stage: "SCAN",
          level: /FAIL/.test(ev.type) ? "warn" : /COMPLETE|VERIFIED|PASS/.test(ev.type) ? "success" : "info",
          message: ev.message,
          payload: ev.payload,
        })
      }
      if (skillAudit.ok) {
        for (const p of skillAudit.pipelineFindings) {
          skillFindings.push({
            tool: "cf-skill",
            ruleId: p.ruleId,
            category: p.category,
            severity: p.severity,
            title: p.title,
            description: p.description,
            filePath: p.filePath,
            line: p.line,
            evidence: p.evidence,
            fixHint: p.fixHint,
          })
        }
        scan.coverage.push({ tool: "cf-skill", filesScanned: scan.filesScanned, findings: skillFindings.length })
      }
      skillSummary = {
        ok: skillAudit.ok,
        stats: skillAudit.stats,
        ledgerStats: skillAudit.ledgerStats,
        validators: skillAudit.validators.map((v) => ({ tool: v.tool, pass: v.pass, output: v.output.slice(0, 200) })),
        outputDir: path.relative(process.cwd(), skillAudit.outputDir ?? path.join(".aegis-audit", runId)),
      }
    } catch (skillError) {
      await emit("SKILL_AUDIT_FAILED", {
        stage: "SCAN",
        level: "warn",
        message: `Cloudflare security-audit-skill integration failed (${skillError instanceof Error ? skillError.message : String(skillError)}) — run continues on driver findings only`,
      })
    }

    const allMerged = dedupFindings([...scan.findings, ...skillFindings])
    // blind spots: what this scan did NOT cover — reported so blind spots stay visible (PRD section 4)
    const depFiles = files.filter((f) => /(requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/i.test(f.path))
    const nonPython = files.filter((f) => !f.path.endsWith(".py"))
    const blindSpots: string[] = []
    if (nonPython.length > 0) {
      blindSpots.push(
        `${nonPython.length} non-Python file(s) were outside the bandit/semgrep rule surface — gitleaks and the cf-skill source audit still covered them.`,
      )
    }
    if (depFiles.length === 0) {
      blindSpots.push(
        "No dependency manifest (requirements.txt / pyproject.toml / Pipfile) found — pip-audit + OSV had nothing to audit this run (dependency CVE coverage: none).",
      )
    }
    if (files.length >= 400) {
      blindSpots.push("Snapshot capped at 400 files — a larger repository may have been only partially traversed.")
    }
    blindSpots.push(
      "Binary files, files above 200KB and vendored directories (.git, node_modules, __pycache__, .venv) are excluded from analysis by policy.",
    )
    if (run.mode === "REPORT_ONLY") {
      blindSpots.push("Report-only mode — sandbox verification and auto-fix were not exercised this run.")
    }
    // Security hardening (audit run-1): per-run cap on derived findings — a crafted repo
    // of repeated matching lines previously materialized unbounded rows/events. The
    // truncation is surfaced as an event so blind spots stay visible.
    const MAX_FINDINGS_PER_RUN = 2000
    const merged = allMerged.slice(0, MAX_FINDINGS_PER_RUN)
    if (allMerged.length > merged.length) {
      await emit("SCAN_TRUNCATED", {
        stage: "SCAN",
        level: "warn",
        message: `Derived findings capped at ${MAX_FINDINGS_PER_RUN} (${allMerged.length} raw after dedup) — remaining findings not materialized this run`,
        payload: { raw: allMerged.length, capped: merged.length },
      })
    }
    const findingIdByRef = new Map<string, string>()
    if (merged.length > 0) {
      // batch insert: IDs are generated client-side so createMany needs no row returns —
      // N sequential inserts collapse into a single round trip
      const rows = merged.map((m) => ({
        id: randomUUID(),
        runId,
        fingerprint: m.fingerprint,
        dedupGroup: m.fingerprint,
        tool: m.primary.tool,
        toolsJson: JSON.stringify(m.tools),
        ruleId: m.ruleIds.join("+"),
        category: m.primary.category,
        title: m.primary.title,
        description: m.primary.description,
        filePath: m.primary.filePath,
        line: m.primary.line,
        endLine: m.primary.endLine ?? m.primary.line,
        evidence: redactText(m.primary.evidence, files),
        severityInitial: m.primary.severity,
        severity: m.primary.severity,
        cve: m.primary.cve ?? null,
        fixHint: m.primary.fixHint ? redactText(m.primary.fixHint, files) : null,
        fixable: true,
        status: "DETECTED",
      }))
      await db.finding.createMany({ data: rows }).catch(() => {})
      merged.forEach((m, i) => findingIdByRef.set(m.refId, rows[i].id))
    }

    // ---- TRIAGE (LLM-assisted dedup/classification/FP-suppression)
    await setRun({ status: "TRIAGING" })
    await emit("STAGE_STARTED", { stage: "TRIAGE", message: `Triage engine engaged (${merged.length} merged findings after cross-tool dedup)` })
    const triage = await triageFindings(merged, files, { apiKey: settings.groqApiKey, model: settings.groqModel })
    addCost(budget, triage.costUsd)
    await db.llmCall.create({
      data: {
        runId,
        stage: "TRIAGE",
        provider: triage.provider,
        model: triage.model,
        promptTokens: triage.promptTokens,
        completionTokens: triage.completionTokens,
        latencyMs: triage.latencyMs,
        ok: !triage.degraded,
        error: triage.error,
        degraded: triage.degraded,
      },
    }).catch(() => {})
    if (triage.degraded) {
      await emit("LLM_DEGRADED", {
        stage: "TRIAGE",
        level: "warn",
        message: `All LLM providers unavailable (${triage.error ?? "no provider"}) — triage served by the self-hosted heuristic engine`,
        payload: { model: triage.model },
      })
    } else if (triage.provider === "ZAI") {
      // Groq unreachable (or no key) — the router chained onto the built-in
      // platform bridge, so full LLM triage is still active.
      await emit("LLM_ROUTER_ENGAGED", {
        stage: "TRIAGE",
        level: "info",
        message: `${settings.groqApiKey ? "Groq unreachable from this network — r" : "No Groq key configured — r"}outer engaged the built-in platform LLM bridge (${triage.model}); full LLM triage and patch synthesis active`,
        payload: { provider: "ZAI", model: triage.model },
      })
    }
    // O(1) lookups for the triage pass
    const mergedByRef = new Map(merged.map((m) => [m.refId, m]))
    // ---- deterministic severity floor (PRD section 4: credential exposure = Critical).
    // Applied after the LLM decisions so no provider can under-rate embedded
    // credentials — scanners keep ground truth, triage records reasoning, and the
    // upgrade path fires the pluggable notifier immediately.
    for (const d of triage.decisions) {
      const m = mergedByRef.get(d.refId)
      if (!m || d.suppress) continue
      const isEmbeddedCredential =
        m.primary.category === "hardcoded-secret" &&
        m.ruleIds.some((r) => r === "GL-006" || r === "GL-009") &&
        !/example|placeholder/i.test(m.primary.evidence)
      if (isEmbeddedCredential && d.severity !== "CRITICAL") {
        d.severity = "CRITICAL"
        d.reasoning = `${d.reasoning} [policy floor] Embedded database / signing credentials are direct credential exposure — severity floored to CRITICAL per the PRD severity definition.`
        d.confidence = Math.max(d.confidence ?? 0, 0.9)
      }
    }
    for (const d of triage.decisions) {
      const id = findingIdByRef.get(d.refId)
      if (!id) continue
      const m = mergedByRef.get(d.refId)
      const upgraded = m && d.severity !== m.primary.severity
      await db.finding
        .update({
          where: { id },
          data: {
            severity: d.severity,
            reasoning: d.reasoning,
            confidence: d.confidence,
            suppressed: d.suppress,
            status: d.suppress ? "SUPPRESSED" : "TRIAGED",
          },
        })
        .catch(() => {})
      if (d.suppress) {
        await emit("TRIAGE_SUPPRESSED", {
          stage: "TRIAGE",
          level: "warn",
          message: `${d.refId} suppressed as probable false positive (confidence ${d.confidence.toFixed(2)})`,
          payload: { refId: d.refId, reasoning: d.reasoning, confidence: d.confidence },
        })
      } else if (upgraded) {
        await emit("SEVERITY_ADJUSTED", {
          stage: "TRIAGE",
          level: d.severity === "CRITICAL" ? "error" : "warn",
          message: `${d.refId} severity ${m!.primary.severity} -> ${d.severity} (triage reasoning recorded)`,
          payload: { refId: d.refId, from: m!.primary.severity, to: d.severity, reasoning: d.reasoning },
        })
        if (d.severity === "CRITICAL") {
          await notifier.notifyCritical({
            refId: d.refId,
            title: m!.primary.title,
            filePath: m!.primary.filePath,
            line: m!.primary.line,
            fromSeverity: m!.primary.severity,
            reasoning: d.reasoning,
          })
        }
      }
    }
    await emit("TRIAGE_COMPLETE", {
      stage: "TRIAGE",
      level: "success",
      message: `Triage complete — ${triage.decisions.filter((d) => d.suppress).length} suppressed, severity finalized`,
      payload: { provider: triage.provider, model: triage.model, degraded: triage.degraded, costUsd: triage.costUsd },
    })

    // ---- decision gate
    if (run.mode === "REPORT_ONLY") {
      // one bulk update instead of N per-id round trips
      await db.finding.updateMany({ where: { runId, status: { not: "SUPPRESSED" } }, data: { status: "REPORTED" } }).catch(() => {})
      await emit("MODE_GATE", { stage: "REMEDIATE", level: "info", message: "Report-only mode — decision gate routes directly to reporting; no remediation attempted" })
    } else {
      // ---- REMEDIATE -> VERIFY loop
      await setRun({ status: "REMEDIATING" })
      await emit("MODE_GATE", {
        stage: "REMEDIATE",
        level: "info",
        message: "Auto-fix mode — remediation loop begins (3 attempts max, budget checked before every attempt)",
      })

      const decisionByRef = new Map(triage.decisions.map((d) => [d.refId, d]))
      const eligible = merged.filter((m) => {
        const d = decisionByRef.get(m.refId)
        return d && !d.suppress
      })

      for (const m of eligible) {
        const d = decisionByRef.get(m.refId)!
        const findingId = findingIdByRef.get(m.refId)!

        // policy path gate: auth-critical code is never auto-patched without human review
        if (isProtectedPath(m.primary.filePath, settings.protectedPaths)) {
          await db.escalation
            .create({ data: { runId, findingId, reason: "POLICY_PROTECTED_PATH", note: `Protected path ${m.primary.filePath}: AEGIS policy requires human review for auth-critical code.` } })
            .catch(() => {})
          await db.finding.update({ where: { id: findingId }, data: { status: "ESCALATED" } }).catch(() => {})
          await emit("ESCALATION_CREATED", {
            stage: "REMEDIATE",
            level: "warn",
            message: `${m.refId} escalated — policy protected path (${m.primary.filePath})`,
            payload: { refId: m.refId, reason: "POLICY_PROTECTED_PATH" },
          })
          continue
        }

        const attemptRecords: SandboxGate[][] = []
        let verified = false
        let failureContext: string | undefined
        let noTemplate = false

        for (let attemptNo = 1; attemptNo <= settings.budgets.maxAttemptsPerFinding; attemptNo++) {
          const gate = budgetCheck(budget, attemptNo - 1)
          if (!gate.allowed) {
            await emit("BUDGET_BREACH", {
              stage: "REMEDIATE",
              level: "error",
              message: `Budget breach for ${m.refId} (${gate.reason}) — escalating with full attempt history`,
              payload: { refId: m.refId, reason: gate.reason, spentUsd: budget.spentUsd },
            })
            await db.remediationAttempt
              .create({
                data: {
                  runId,
                  findingId,
                  attemptNo,
                  strategy: "ABORTED",
                  patchJson: JSON.stringify({ edits: [], rationale: "budget exhausted before attempt" }),
                  model: settings.groqModel,
                  result: "ABORTED_BUDGET",
                  failureContext: gate.reason,
                  verified: false,
                },
              })
              .catch(() => {})
            await db.escalation
              .create({ data: { runId, findingId, reason: "BUDGET_EXHAUSTED", note: gate.reason } })
              .catch(() => {})
            await db.finding.update({ where: { id: findingId }, data: { status: "ESCALATED" } }).catch(() => {})
            await emit("ESCALATION_CREATED", {
              stage: "REMEDIATE",
              level: "warn",
              message: `${m.refId} escalated (BUDGET_EXHAUSTED)`,
              payload: { refId: m.refId, reason: "BUDGET_EXHAUSTED" },
            })
            break
          }

          await emit("PATCH_DRAFTING", {
            stage: "REMEDIATE",
            level: "info",
            message: `${m.refId} attempt ${attemptNo}: drafting patch (${m.primary.title})`,
            payload: { refId: m.refId, attemptNo },
          })

          // LLM router: Groq first, deterministic templates as the self-hosted fallback
          const draftResult = await draftPatchLlm(m, files, {
            apiKey: settings.groqApiKey,
            model: settings.groqModel,
            failureContext,
            attempt: attemptNo,
          })
          let draft = draftResult.data
          if (draftResult.provider === "FALLBACK_HEURISTIC") {
            const tpl = templatePatch(m, files)
            if (!tpl) {
              noTemplate = true
              await db.llmCall
                .create({
                  data: { runId, stage: "REMEDIATE", provider: draftResult.provider, model: draftResult.model, ok: false, degraded: true, error: draftResult.error },
                })
                .catch(() => {})
              break
            }
            draft = tpl
            addCost(budget, 0)
          } else {
            addCost(budget, estimateCostUsd(draftResult.model, draftResult.usage))
            await db.llmCall
              .create({
                data: {
                  runId,
                  stage: "REMEDIATE",
                  provider: draftResult.provider,
                  model: draftResult.model,
                  promptTokens: draftResult.usage.promptTokens,
                  completionTokens: draftResult.usage.completionTokens,
                  latencyMs: draftResult.usage.latencyMs,
                  ok: draftResult.ok,
                  error: draftResult.error,
                  degraded: draftResult.degraded,
                },
              })
              .catch(() => {})
            if (draftResult.degraded) {
              await emit("LLM_DEGRADED", {
                stage: "REMEDIATE",
                level: "warn",
                message: `All LLM providers unavailable during remediation (${draftResult.error}) — template engine drafting for ${m.refId}`,
              })
            }
          }
          if (!draft || draft.edits.length === 0) {
            noTemplate = true
            break
          }
          if (draftResult.provider === "FALLBACK_HEURISTIC" && draft.edits.length === 0) {
            noTemplate = true
            break
          }

          await emit("PATCH_DRAFTED", {
            stage: "REMEDIATE",
            level: "info",
            message: `${m.refId} attempt ${attemptNo}: patch drafted (${draft.edits.length} edit(s), ${draft.strategy}) — ${draft.rationale.slice(0, 90)}…`,
            payload: { refId: m.refId, attemptNo, strategy: draft.strategy, edits: draft.edits.length },
          })

          // ---- VERIFY in the sandbox
          const verify = await sandboxVerify({
            files,
            edits: draft.edits,
            target: {
              filePath: m.primary.filePath,
              rules: m.sources.map((s) => ({ tool: s.tool, ruleId: s.ruleId })),
              severity: d.severity,
            },
            protectedPaths: settings.protectedPaths,
            sandboxDir: "/tmp/aegis-sandbox",
            secretBindings,
          })
          attemptRecords.push(verify.gates)

          if (verify.result === "PASSED") {
            files = verify.patchedFiles
            await db.remediationAttempt
              .create({
                data: {
                  runId,
                  findingId,
                  attemptNo,
                  strategy: draft.strategy,
                  patchJson: JSON.stringify(draft),
                  model: draftResult.provider === "FALLBACK_HEURISTIC" ? "aegis-heuristic-v1" : draftResult.model,
                  result: "PASSED",
                  verified: true,
                  costUsd: draftResult.provider === "FALLBACK_HEURISTIC" ? 0 : estimateCostUsd(draftResult.model, draftResult.usage),
                  durationMs: draftResult.usage.latencyMs,
                },
              })
              .catch(() => {})
            await db.finding.update({ where: { id: findingId }, data: { status: "VERIFIED" } }).catch(() => {})
            await emit("SANDBOX_VERIFY", {
              stage: "VERIFY",
              level: "success",
              message: `${m.refId} VERIFIED — all gates passed (apply, tests, re-scan, policy)`,
              payload: { refId: m.refId, attemptNo, gates: verify.gates, result: "PASSED" },
            })
            // Critical findings still require mandatory human review before merge (PRD §4)
            if (d.severity === "CRITICAL") {
              await db.escalation
                .create({ data: { runId, findingId, reason: "CRITICAL_SEVERITY", note: "Verified critical fix — human review mandatory before merge (same-day SLA)." } })
                .catch(() => {})
              await emit("ESCALATION_CREATED", {
                stage: "VERIFY",
                level: "warn",
                message: `${m.refId} verified but Critical — escalated for mandatory human review before merge`,
                payload: { refId: m.refId, reason: "CRITICAL_SEVERITY" },
              })
            }
            verified = true
            break
          }

          // failure context feeds forward into the next attempt
          failureContext = verify.failureContext
          await db.remediationAttempt
            .create({
              data: {
                runId,
                findingId,
                attemptNo,
                strategy: draft.strategy,
                patchJson: JSON.stringify(draft),
                model: draftResult.provider === "FALLBACK_HEURISTIC" ? "aegis-heuristic-v1" : draftResult.model,
                result: verify.result,
                failureContext: verify.failureContext,
                verified: false,
                costUsd: draftResult.provider === "FALLBACK_HEURISTIC" ? 0 : estimateCostUsd(draftResult.model, draftResult.usage),
                durationMs: draftResult.usage.latencyMs,
              },
            })
            .catch(() => {})
          await emit("SANDBOX_VERIFY", {
            stage: "VERIFY",
            level: "warn",
            message: `${m.refId} attempt ${attemptNo} FAILED (${verify.result}) — failure context feeds forward`,
            payload: { refId: m.refId, attemptNo, gates: verify.gates, result: verify.result, failureContext: verify.failureContext },
          })
        }

        if (!verified && !noTemplate) {
          await db.escalation
            .create({ data: { runId, findingId, reason: "MAX_ATTEMPTS", note: "3-attempt limit exhausted; full attempt history attached." } })
            .catch(() => {})
          await db.finding.update({ where: { id: findingId }, data: { status: "ESCALATED" } }).catch(() => {})
          await emit("ESCALATION_CREATED", {
            stage: "REMEDIATE",
            level: "warn",
            message: `${m.refId} escalated (MAX_ATTEMPTS) — 3-attempt limit exhausted`,
            payload: { refId: m.refId, reason: "MAX_ATTEMPTS" },
          })
        } else if (!verified && noTemplate) {
          await db.escalation
            .create({ data: { runId, findingId, reason: "NO_SAFE_TEMPLATE", note: "No deterministic safe template for this finding class; human design required." } })
            .catch(() => {})
          await db.finding.update({ where: { id: findingId }, data: { status: "ESCALATED" } }).catch(() => {})
          await emit("ESCALATION_CREATED", {
            stage: "REMEDIATE",
            level: "warn",
            message: `${m.refId} escalated (NO_SAFE_TEMPLATE) — requires human patch design`,
            payload: { refId: m.refId, reason: "NO_SAFE_TEMPLATE" },
          })
        }
      }
    }

    // ---- REPORT
    await setRun({ status: "REPORTING" })
    await emit("STAGE_STARTED", { stage: "REPORT", message: "Compiling Markdown / HTML report and PR payload" })

    const dbFindings = await db.finding.findMany({ where: { runId }, orderBy: [{ severity: "desc" }, { filePath: "asc" }, { line: "asc" }] })
    const dbAttempts = await db.remediationAttempt.findMany({ where: { runId }, orderBy: { attemptNo: "asc" } })
    const dbEscalations = await db.escalation.findMany({ where: { runId } })
    const attemptByFinding = new Map<string, typeof dbAttempts>()
    for (const a of dbAttempts) {
      const arr = attemptByFinding.get(a.findingId)
      if (arr) arr.push(a)
      else attemptByFinding.set(a.findingId, [a])
    }
    const escalationByFinding = new Map(dbEscalations.filter((e) => e.findingId).map((e) => [e.findingId as string, e]))
    const findingRecords: FindingRecord[] = dbFindings.map((f) => {
      const attempts = attemptByFinding.get(f.id) ?? []
      const verifiedAttempt = attempts.find((a) => a.verified)
      let finalPatch: FindingRecord["finalPatch"] = null
      if (verifiedAttempt) {
        try {
          const parsed = JSON.parse(verifiedAttempt.patchJson) as { edits: { filePath: string; oldCode: string; newCode: string }[]; rationale: string; riskNotes?: string }
          finalPatch = { edits: parsed.edits, rationale: parsed.rationale, riskNotes: parsed.riskNotes }
        } catch {
          finalPatch = null
        }
      }
      const esc = escalationByFinding.get(f.id)
      return {
        refId: f.fingerprint,
        tool: f.tool,
        tools: safeTools(f.toolsJson),
        ruleId: f.ruleId,
        category: f.category,
        severity: f.severity as FindingRecord["severity"],
        severityInitial: f.severityInitial as FindingRecord["severity"],
        title: f.title,
        description: f.description,
        filePath: f.filePath,
        line: f.line,
        evidence: f.evidence,
        cve: f.cve,
        reasoning: f.reasoning,
        confidence: f.confidence,
        fixHint: f.fixHint ?? null,
        suppressed: f.suppressed,
        status: f.status,
        escalationReason: esc?.reason ?? null,
        attempts: attempts.map((a) => ({
          attemptNo: a.attemptNo,
          result: a.result,
          strategy: a.strategy,
          failureContext: a.failureContext,
          rationale: describeAttempt(a),
          gates: [],
        })),
        finalPatch,
      }
    })

    const durationMs = Date.now() - budget.startedAtMs
    // per-rule FP drift across the findings store + critical-alert count for this run
    const [fpTotals, fpSuppressed, criticalAlerts] = await Promise.all([
      db.finding.groupBy({ by: ["ruleId", "tool"], _count: { _all: true } }),
      db.finding.groupBy({ by: ["ruleId", "tool"], where: { suppressed: true }, _count: { _all: true } }),
      db.event.count({ where: { runId, type: "CRITICAL_ALERT" } }),
    ])
    const suppressedByKey = new Map(fpSuppressed.map((g) => [`${g.tool}::${g.ruleId}`, g._count._all]))
    const fpStats = fpTotals
      .map((g) => {
        const total = g._count._all
        const suppressed = suppressedByKey.get(`${g.tool}::${g.ruleId}`) ?? 0
        return { ruleId: g.ruleId, tool: g.tool, total, suppressed, fpRate: total > 0 ? (suppressed / total) * 100 : 0 }
      })
      .sort((a, b) => b.fpRate - a.fpRate || b.total - a.total)
    const reportInput = {
      repoName: repo.repoName,
      repoUrl: run.repoUrl,
      commitSha: repo.commitSha,
      mode: run.mode as "REPORT_ONLY" | "AUTO_FIX",
      engineMode: triage.provider,
      model: triage.model,
      durationMs,
      costUsd: budget.spentUsd,
      filesScanned: scan.filesScanned,
      locScanned: scan.locScanned,
      coverage: scan.coverage.map((c) => ({ ...c, role: roleFor(c.tool) })),
      findings: findingRecords,
      budgets: settings.budgets,
      fpStats,
      blindSpots,
      criticalAlerts,
      skillAudit: skillSummary,
    }
    const reportMd = buildMarkdownReport(reportInput)
    const reportHtml = buildHtmlReport(reportInput)
    const prPayload = run.mode === "AUTO_FIX" ? buildPrPayload(reportInput) : null

    await setRun({
      status: "COMPLETED",
      finishedAt: new Date(),
      wallClockMs: durationMs,
      costUsd: budget.spentUsd,
      engineMode: reportInput.engineMode,
      llmModel: triage.model,
      reportMd,
      reportHtml,
      prPayloadJson: prPayload ? JSON.stringify(prPayload) : null,
    })
    await emit("PR_PREPARED", {
      stage: "REPORT",
      level: "success",
      message: prPayload
        ? `Pull request staged: ${reportInput.findings.filter((f) => f.status === "VERIFIED").length} verified fixes grouped into one PR (AEGIS never merges)`
        : "Report-only run — no PR",
    })
    await emit("REPORT_READY", {
      stage: "REPORT",
      level: "success",
      message: `Report ready — Markdown + HTML + PDF export (${(durationMs / 1000).toFixed(1)}s, $${budget.spentUsd.toFixed(4)})`,
    })
    await emit("RUN_COMPLETED", {
      stage: "REPORT",
      level: "success",
      message: "Run completed — findings store and event log sealed",
      payload: {
        findings: findingRecords.length,
        verified: findingRecords.filter((f) => f.status === "VERIFIED").length,
        escalated: dbEscalations.length,
        suppressed: findingRecords.filter((f) => f.suppressed).length,
        durationMs,
        costUsd: budget.spentUsd,
      },
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    // attribute the failure to the stage the pipeline was actually in (was hardcoded
    // to REPORT — a mid-scan/patch crash was mislabeled as a dispatch failure)
    await emit("RUN_FAILED", { stage: emitStageFor(lastStatus), level: "error", message: `Run failed: ${message}` })
    await setRun({ status: "FAILED", failedStage: graphStageIdx(lastStatus), error: message, finishedAt: new Date() })
  } finally {
    // Security hardening (audit run-2): the admission semaphore previously leaked —
    // run ids were added but never removed, so enforcement would have permanently
    // rejected all traffic once the cap was crossed. Release the slot on every exit path.
    ACTIVE_RUNS.delete(runId)
    // Security hardening (audit run-2 follow-up): the clone is cleaned up on EVERY
    // outcome — the success-only call previously retained full repo trees under /tmp
    // whenever a later stage threw (sandbox fs errors, prisma SQLITE_BUSY, …).
    if (repo?.cleanup) {
      try {
        await repo.cleanup()
      } catch {
        /* cleanup is best-effort — never mask the run's own outcome */
      }
    }
  }
}

function safeTools(toolsJson: string | null): string[] {
  if (!toolsJson) return []
  try {
    const v = JSON.parse(toolsJson)
    return Array.isArray(v) ? v.map(String) : []
  } catch {
    return []
  }
}

/** 5-stage execution-graph index for a live run status (mirrors STAGES in bits.tsx). */
function graphStageIdx(status: string): number {
  switch (status) {
    case "TRIAGING":
      return 1
    case "REMEDIATING":
      return 2
    case "REPORTING":
      return 4
    default:
      // RESOLVING / CLONING / SCANNING — pre-graph or stage 0
      return 0
  }
}

/** Event-store stage name matching the run's live status. */
function emitStageFor(status: string): string {
  switch (status) {
    case "RESOLVING":
      return "RESOLVE"
    case "CLONING":
      return "CLONE"
    case "SCANNING":
      return "SCAN"
    case "TRIAGING":
      return "TRIAGE"
    case "REMEDIATING":
      return "REMEDIATE"
    case "REPORTING":
      return "REPORT"
    default:
      return "REPORT"
  }
}

function roleFor(tool: string): string {
  switch (tool) {
    case "gitleaks":
      return "hardcoded secrets"
    case "bandit":
      return "python misuse"
    case "semgrep":
      return "injection & auth"
    case "pip-audit":
      return "dependency CVEs"
    case "cf-skill":
      return "six-phase source audit (vendored Cloudflare skill)"
    default:
      return "scanner"
  }
}

function describeAttempt(a: { result: string; strategy: string; failureContext?: string | null }): string {
  if (a.result === "PASSED") return "All sandbox gates passed (apply, tests, re-scan, policy)."
  return a.failureContext ?? a.result
}

export const engineRuntime = { executeRun, loadEngineSettings }
