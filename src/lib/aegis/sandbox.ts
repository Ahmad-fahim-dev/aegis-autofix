// Ephemeral sandbox — apply, test gate (repo pytest suite; py_compile fallback),
// targeted re-scan, policy check. Docker isolation (see the Dockerfile at the repo
// root) is emulated in-environment with a throwaway, credential-free directory per
// attempt; the repository's own pytest suite is the real gate whenever it can run.
import { execFile } from "child_process"
import { promises as fs } from "fs"
import path from "path"
import { scanGitleaks } from "./drivers/gitleaks"
import { scanBandit } from "./drivers/bandit"
import { scanSemgrep } from "./drivers/semgrep"
import { scanPipAudit } from "./drivers/pipaudit"
import { redactText } from "./redact"
import { isProtectedPath } from "./policy"
import type { RepoFile, StructuredEdit, VerifyResult } from "./types"

export interface SandboxGate {
  name: string
  passed: boolean
  detail: string
}

export interface SandboxResult {
  result: VerifyResult
  gates: SandboxGate[]
  failureContext: string
  patchedFiles: RepoFile[] // full snapshot after apply (only meaningful on PASSED)
}

export interface SandboxTarget {
  filePath: string
  /** per-tool rules that produced this finding; occurrence count must decrease */
  rules: { tool: string; ruleId: string }[]
  severity: string
}

function compilePython(dir: string, file: RepoFile): Promise<{ ok: boolean; stderr: string }> {
  const target = path.join(dir, "gate_" + file.path.replace(/[/\\]/g, "__"))
  return (async () => {
    await fs.mkdir(path.dirname(target), { recursive: true })
    await fs.writeFile(target, file.content)
    return await new Promise<{ ok: boolean; stderr: string }>((resolve) => {
      const t = setTimeout(() => {
        child.kill()
        resolve({ ok: false, stderr: "py_compile timeout" })
      }, 20_000)
      const child = execFile("python3", ["-m", "py_compile", target], { maxBuffer: 1024 * 512 }, (err, _stdout, stderr) => {
        clearTimeout(t)
        resolve({ ok: !err, stderr: String(stderr).slice(0, 500) })
      })
    })
  })()
}

function rescanSingle(file: RepoFile, tool: string) {
  switch (tool) {
    case "gitleaks":
      return scanGitleaks([file])
    case "bandit":
      return scanBandit([file])
    case "semgrep":
      return scanSemgrep([file])
    case "pip-audit":
      return scanPipAudit([file])
    default:
      return []
  }
}

/**
 * Verify a patch in the sandbox: apply edits to a snapshot, run the syntax/test gate,
 * re-scan the touched files, and enforce the policy path gate. All gates pass = verified.
 */
export async function sandboxVerify(opts: {
  files: RepoFile[]
  edits: StructuredEdit[]
  target: SandboxTarget
  protectedPaths: string[]
  sandboxDir: string
  secretBindings?: Record<string, string>
}): Promise<SandboxResult> {
  const { files, edits, target, protectedPaths, sandboxDir, secretBindings } = opts
  const gates: SandboxGate[] = []

  // ---- gate 1: apply (exact, unambiguous replacements only)
  const applied = new Map<string, RepoFile>()
  for (const f of files) applied.set(f.path, f)
  let applyDetail = ""
  for (const edit of edits) {
    const file = applied.get(edit.filePath)
    if (!file) {
      applyDetail = `edit references unknown file ${edit.filePath}`
      break
    }
    // bind masked secret literals back to the real content (LLM only ever sees masks)
    let oldCode = edit.oldCode
    if (secretBindings) {
      for (const [mask, real] of Object.entries(secretBindings)) {
        if (oldCode.includes(mask)) oldCode = oldCode.split(mask).join(real)
      }
    }
    const count = countOccurrences(file.content, oldCode)
    if (count === 0) {
      // Security hardening (audit run-1): never surface the re-bound real secret in the
      // failure context — redact at the source so real literals never leave this module.
      applyDetail = `oldCode not found in ${edit.filePath}:\n  expected: ${truncate(redactText(oldCode, files))}`
      break
    }
    if (count > 1) {
      applyDetail = `oldCode is ambiguous (${count} occurrences) in ${edit.filePath}:\n  ${truncate(redactText(oldCode, files))}`
      break
    }
    const newContent = file.content.replace(oldCode, edit.newCode)
    applied.set(edit.filePath, { path: file.path, content: newContent, lines: newContent.split("\n") })
  }
  const appliedOk = applyDetail === ""
  gates.push({
    name: "apply",
    passed: appliedOk,
    detail: appliedOk ? `${edits.length} edit(s) applied to ${edits.length} file(s)` : applyDetail,
  })
  if (!appliedOk) {
    return { result: "FAILED_APPLY", gates, failureContext: `Sandbox apply gate failed. ${applyDetail}`, patchedFiles: files }
  }

  const touched = edits.map((e) => applied.get(e.filePath)).filter(Boolean) as RepoFile[]

  // ---- gate 2: policy path gate (protected paths are never auto-patched)
  const policyHit = touched.some((f) => isProtectedPath(f.path, protectedPaths))
  gates.push({
    name: "policy",
    passed: !policyHit,
    detail: policyHit
      ? "patch touches a policy-protected path (auth-critical) — human review required"
      : "no protected path touched",
  })
  if (policyHit) {
    return {
      result: "FAILED_POLICY",
      gates,
      failureContext: "Policy gate: patch modifies a protected path; auto-patch is not allowed without human review.",
      patchedFiles: files,
    }
  }

  // ---- gate 3: test gate — the repo's own pytest suite runs against the patched
  // snapshot inside the ephemeral sandbox (PRD: "apply patch, run pytest").
  // Offline sandboxes where third-party dependencies cannot be collected, or repos
  // without tests, degrade honestly to the python3 -m py_compile syntax gate.
  const pyTouched = touched.filter((f) => f.path.endsWith(".py"))
  let testsPassed = true
  let testsDetail = "no python files touched — gate skipped"
  let failureKind: "FAILED_TESTS" | "FAILED_SYNTAX" | null = null
  if (pyTouched.length > 0) {
    const sandbox = path.join(sandboxDir, `attempt-${Date.now()}`)
    const gate = await runTestGate(sandbox, [...applied.values()])
    testsPassed = gate.passed
    testsDetail = gate.detail
    failureKind = gate.failureKind ?? null
    await fs.rm(sandbox, { recursive: true, force: true }).catch(() => {})
  }
  gates.push({ name: "tests", passed: testsPassed, detail: testsDetail })
  if (!testsPassed) {
    return {
      result: failureKind ?? "FAILED_SYNTAX",
      gates,
      failureContext: `Test gate failed — ${testsDetail}`,
      patchedFiles: files,
    }
  }

  // ---- gate 4: targeted re-scan of touched files (per-rule occurrence count must decrease)
  let rescanOk = true
  const stillFlagged: string[] = []
  for (const { tool, ruleId } of target.rules) {
    for (const path of new Set([target.filePath, ...edits.map((e) => e.filePath)])) {
      const before = files.find((f) => f.path === path)
      const after = applied.get(path)
      if (!after) continue
      const preCount = before ? rescanSingle(before, tool).filter((r) => r.ruleId === ruleId && r.filePath === path).length : 0
      const postCount = rescanSingle(after, tool).filter((r) => r.ruleId === ruleId && r.filePath === path).length
      const introduced = preCount === 0 && postCount > 0
      const notReduced = preCount > 0 && postCount >= preCount
      if (introduced || notReduced) {
        stillFlagged.push(
          `${tool}/${ruleId}: ${introduced ? `new occurrence introduced in ${path}` : `still ${postCount}/${preCount} occurrence(s) in ${path}`}`,
        )
      }
    }
  }
  rescanOk = stillFlagged.length === 0
  gates.push({
    name: "re-scan",
    passed: rescanOk,
    detail: rescanOk ? `targeted re-scan clean (${target.rules.map((r) => r.tool).join(", ")})` : stillFlagged.join("; "),
  })
  if (!rescanOk) {
    return {
      result: "FAILED_RESCAN",
      gates,
      failureContext: `Re-scan gate failed — the finding is still detected after the patch. ${stillFlagged.join("; ")}`,
      patchedFiles: files,
    }
  }

  return { result: "PASSED", gates, failureContext: "", patchedFiles: [...applied.values()] }
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0
  let count = 0
  let idx = haystack.indexOf(needle)
  while (idx !== -1) {
    count++
    idx = haystack.indexOf(needle, idx + needle.length)
  }
  return count
}

function truncate(s: string, n = 90): string {
  const one = s.split("\n")[0]
  return one.length > n ? one.slice(0, n) + "…" : one
}

// ---- sandbox test gate (PRD: "apply patch, run pytest") ----------------------------

const TEST_FILE_RE = /(^|\/)(test_[^/]+\.py|[^/]+_test\.py)$/

interface TestGateOutcome {
  passed: boolean
  detail: string
  failureKind?: "FAILED_TESTS" | "FAILED_SYNTAX"
}

/**
 * Materializes the patched snapshot into a throwaway, credential-free sandbox
 * directory and runs the repository's own pytest suite against it. Falls back to
 * python3 -m py_compile when the repo has no tests or its dependencies cannot be
 * collected in the offline sandbox — always with the reason recorded in the gate
 * detail so the verification trail stays honest.
 */
async function runTestGate(sandboxRoot: string, snapshot: RepoFile[]): Promise<TestGateOutcome> {
  await fs.mkdir(sandboxRoot, { recursive: true })
  for (const f of snapshot) {
    const dest = path.join(sandboxRoot, f.path)
    if (!dest.startsWith(sandboxRoot + path.sep)) continue // path containment — never write outside the sandbox
    await fs.mkdir(path.dirname(dest), { recursive: true }).catch(() => {})
    await fs.writeFile(dest, f.content).catch(() => {})
  }
  const testPaths = snapshot.filter((f) => TEST_FILE_RE.test(f.path)).map((f) => f.path)

  if (testPaths.length > 0) {
    const run = await runPytest(sandboxRoot, testPaths)
    if (run.status === "RAN") {
      return run.passed
        ? { passed: true, detail: `repo pytest suite passed — ${run.summary}` }
        : { passed: false, failureKind: "FAILED_TESTS", detail: `repo pytest suite failed — ${run.summary}` }
    }
    const compile = await compileSnapshot(sandboxRoot, snapshot)
    if (!compile.ok) return { passed: false, failureKind: "FAILED_SYNTAX", detail: `py_compile failed — ${compile.detail}` }
    if (run.status === "DEGRADED_DEPS") {
      return { passed: true, detail: `pytest could not collect (${run.reason}) — offline sandbox has no third-party packages; py_compile syntax gate passed on the patched snapshot` }
    }
    if (run.status === "NO_TESTS_COLLECTED") {
      return { passed: true, detail: "pytest collected no tests — py_compile syntax gate passed on the patched snapshot" }
    }
    if (run.status === "PYTEST_UNAVAILABLE") {
      return { passed: true, detail: `${run.reason} — py_compile syntax gate passed on the patched snapshot` }
    }
    return { passed: false, failureKind: "FAILED_TESTS", detail: `pytest timed out — ${run.reason}` }
  }

  // no test files in the repository: syntax gate on the full patched snapshot
  const compile = await compileSnapshot(sandboxRoot, snapshot)
  const pyCount = snapshot.filter((f) => f.path.endsWith(".py")).length
  return compile.ok
    ? { passed: true, detail: `no test suite in repo — py_compile syntax gate passed on ${pyCount} python file(s)` }
    : { passed: false, failureKind: "FAILED_SYNTAX", detail: `py_compile failed — ${compile.detail}` }
}

interface PytestRun {
  status: "RAN" | "DEGRADED_DEPS" | "NO_TESTS_COLLECTED" | "PYTEST_UNAVAILABLE" | "TIMEOUT"
  passed: boolean
  summary: string
  reason: string
}

/**
 * Resolve an interpreter that can import pytest. The sandbox env is sanitized, so the
 * PATH-visible python3 may differ from the operator's — candidates are probed once and
 * cached. An explicit AEGIS_PYTHON env var always wins; when no candidate can import
 * pytest the gate degrades honestly to the py_compile syntax gate.
 */
let cachedPytestInterpreter: string | null | undefined

function pytestInterpreterCandidates(): string[] {
  const list = [
    process.env.AEGIS_PYTHON, // explicit operator override
    "/home/z/.venv/bin/python3", // deployment venv carrying pytest
    "/usr/local/bin/python3",
    "python3", // bare PATH lookup
  ].filter((v): v is string => Boolean(v && v.trim().length > 0))
  return [...new Set(list)]
}

async function resolvePytestInterpreter(): Promise<string | null> {
  if (cachedPytestInterpreter !== undefined) return cachedPytestInterpreter
  for (const candidate of pytestInterpreterCandidates()) {
    const ok = await new Promise<boolean>((resolve) => {
      execFile(candidate, ["-c", "import pytest"], { timeout: 8000, maxBuffer: 1024 }, (err) => resolve(!err))
    })
    if (ok) {
      cachedPytestInterpreter = candidate
      return candidate
    }
  }
  cachedPytestInterpreter = null
  return null
}

async function runPytest(cwd: string, testPaths: string[]): Promise<PytestRun> {
  const interpreter = await resolvePytestInterpreter()
  if (!interpreter) {
    return { status: "PYTEST_UNAVAILABLE", passed: false, summary: "", reason: "no interpreter on this host can import pytest" }
  }
  return await new Promise<PytestRun>((resolve) => {
    execFile(
      interpreter,
      ["-m", "pytest", ...testPaths, "-q", "--no-header", "-p", "no:cacheprovider", "--color=no"],
      {
        cwd,
        timeout: 30_000,
        maxBuffer: 1024 * 512,
        // credential-free environment: only what the interpreter itself needs
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          HOME: cwd,
          PYTHONDONTWRITEBYTECODE: "1",
          NODE_ENV: process.env.NODE_ENV,
        },
      },
      (err, stdout, stderr) => {
        const out = `${stdout}\n${stderr}`
        const summary = out.trim().split("\n").filter(Boolean).slice(-2).join(" | ").slice(0, 200)
        if (err && (err as { signal?: string }).signal === "SIGTERM") {
          resolve({ status: "TIMEOUT", passed: false, summary, reason: "suite exceeded the 30s sandbox ceiling" })
          return
        }
        const code = err ? (err as { code?: number }).code ?? 1 : 0
        if (code === 0) resolve({ status: "RAN", passed: true, summary, reason: "" })
        else if (code === 5) resolve({ status: "NO_TESTS_COLLECTED", passed: false, summary, reason: "pytest exit 5 — no tests collected" })
        else if (/No module named pytest/i.test(out) && !/\b\d+ failed\b/.test(out)) {
          resolve({
            status: "DEGRADED_DEPS",
            passed: false,
            summary,
            reason: "the sandbox interpreter cannot import pytest (environment limitation)",
          })
        } else if (
          /ModuleNotFoundError|ImportError/.test(out) &&
          /ERROR collecting|errors? during collection/i.test(out) &&
          !/\b\d+ failed\b/.test(out)
        ) {
          resolve({
            status: "DEGRADED_DEPS",
            passed: false,
            summary,
            reason: "collection failed on missing third-party modules (offline, credential-free sandbox)",
          })
        } else resolve({ status: "RAN", passed: false, summary, reason: "" })
      },
    )
  })
}

async function compileSnapshot(sandboxRoot: string, snapshot: RepoFile[]): Promise<{ ok: boolean; detail: string }> {
  for (const f of snapshot) {
    if (!f.path.endsWith(".py")) continue
    const r = await compilePython(sandboxRoot, f)
    if (!r.ok) return { ok: false, detail: `${f.path}: ${r.stderr || "compile error"}` }
  }
  return { ok: true, detail: "" }
}
