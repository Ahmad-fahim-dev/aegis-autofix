// Remediation Engine — drafts a patch per finding (LLM primary, deterministic template fallback),
// then the orchestrator verifies it in the sandbox. Retries carry failure context forward.
import { fixVersionFor } from "./drivers/pipaudit"
import { redactText } from "./redact"
import { llmRoute, estimateCostUsd } from "./groq"
import type { MergedFinding } from "./dedup"
import type { LlmResult, PatchDraft, RepoFile, StructuredEdit } from "./types"

export interface DraftResult {
  draft: PatchDraft
  llm: LlmResult<PatchDraft>
  costUsd: number
}

const SYSTEM = `You are the AEGIS Remediation Engine. You draft minimal, safe patches for findings detected by deterministic scanners in a Python repository.
Rules:
- Copy oldCode EXACTLY from the file, character for character (including indentation). If a secret literal is masked (shown like abcd…ef (34 chars, redacted)), use the masked text verbatim in oldCode; the platform binds it back to the real content.
- Prefer the smallest possible edit that removes the vulnerability without changing behavior.
- Move secrets to os.environ[...] lookups. Parameterize SQL. Use safe_load for YAML. Use secrets module for tokens. Never weaken tests.
- Respond with STRICT JSON: {"edits":[{"filePath":"relative/path","oldCode":"verbatim line(s)","newCode":"replacement"}],"rationale":"why this removes the issue","riskNotes":"residual risk for the human reviewer"}.`

export async function draftPatchLlm(
  merged: MergedFinding,
  files: RepoFile[],
  opts: { apiKey: string; model: string; failureContext?: string; attempt: number },
): Promise<LlmResult<PatchDraft>> {
  const f = merged.primary
  const target = files.find((x) => x.path === f.filePath)
  const fileText = target
    ? target.content.length < 12000
      ? target.content
      : target.lines.slice(Math.max(0, f.line - 60), f.line + 40).join("\n")
    : "(file not available)"

  const user = [
    `Finding ${merged.refId}: ${f.title} (${f.severity})`,
    `Rule: ${merged.ruleIds.join(" + ")} from tools ${merged.tools.join(", ")}`,
    `File: ${f.filePath}, line ${f.line}`,
    `Description: ${f.description}`,
    // Security hardening (audit run-1): every finding-derived section is redacted like
    // the file text — the raw Evidence/failureContext previously egressed secret literals
    // to the provider in the same request whose file section was redacted.
    `Evidence:\n${redactText(f.evidence, files)}`,
    "",
    `Full content of ${f.filePath} (secrets redacted):\n\`\`\`\n${redactText(fileText, files)}\n\`\`\``,
    opts.failureContext
      ? `\nIMPORTANT — previous attempt failed verification:\n${redactText(opts.failureContext, files)}\nFix the cause of that failure in this revised patch.`
      : "",
    "\nDraft the patch now. Respond with the JSON object only.",
  ]
    .filter(Boolean)
    .join("\n")

  return llmRoute<PatchDraft>(
    { apiKey: opts.apiKey, model: opts.model, system: SYSTEM, user, maxTokens: 2200, timeoutMs: 60000 },
    validatePatch(files),
    () => {
      const t = templatePatch(merged, files)
      return {
        data:
          t ?? {
            edits: [],
            rationale: "No deterministic template exists for this finding class; human design required.",
            strategy: "TEMPLATE_FALLBACK",
          },
        reasoning: "All LLM providers unavailable — template engine consulted.",
      }
    },
  )
}

function validatePatch(files: RepoFile[]) {
  return (parsed: unknown): PatchDraft | null => {
    const root = parsed as { edits?: unknown; rationale?: unknown; riskNotes?: unknown }
    if (!root || typeof root !== "object" || !Array.isArray(root.edits)) return null
    if (typeof root.rationale !== "string" || root.rationale.length < 15) return null
    const known = new Set(files.map((x) => x.path))
    const edits: StructuredEdit[] = []
    for (const e of root.edits as Record<string, unknown>[]) {
      const filePath = String(e.filePath ?? "")
      const oldCode = e.oldCode === undefined ? undefined : String(e.oldCode)
      const newCode = e.newCode === undefined ? undefined : String(e.newCode)
      if (!known.has(filePath) || oldCode === undefined || newCode === undefined) return null
      if (oldCode.length === 0 || newCode.length === 0) return null
      edits.push({ filePath, oldCode, newCode })
    }
    if (edits.length === 0) return null
    return {
      edits,
      rationale: root.rationale,
      riskNotes: typeof root.riskNotes === "string" ? root.riskNotes : undefined,
      strategy: "LLM_SINGLE",
    }
  }
}

// ---------------------------------------------------------------------------
// Deterministic template engine (self-hosted / degraded mode)
// ---------------------------------------------------------------------------

export function templatePatch(merged: MergedFinding, files: RepoFile[]): PatchDraft | null {
  const f = merged.primary
  const file = files.find((x) => x.path === f.filePath)
  if (!file) return null
  const rawLine = resolveTargetLine(file, f)

  const mk = (edits: StructuredEdit[], rationale: string, riskNotes?: string): PatchDraft => ({
    edits,
    rationale,
    riskNotes,
    strategy: "TEMPLATE_FALLBACK",
  })
  const single = (newLine: string, rationale: string, riskNotes?: string): PatchDraft | null =>
    mk([{ filePath: f.filePath, oldCode: rawLine, newCode: newLine.trim() === "" ? rawLine : newLine }], rationale, riskNotes)

  const ensureImport = (imports: string): StructuredEdit | null => {
    const mod = imports.replace(/^import\s+/, "").trim()
    if (new RegExp(`^import\\s+${mod}\\b`, "m").test(file.content)) return null
    const anchor = file.lines.find((l) => /^import\s|^from\s/.test(l))
    if (anchor) {
      return { filePath: f.filePath, oldCode: anchor, newCode: `${imports}\n${anchor}` }
    }
    return { filePath: f.filePath, oldCode: file.lines[0] ?? "", newCode: `${imports}\n${file.lines[0] ?? ""}` }
  }

  // ---- hardcoded secrets -> environment lookup
  if (f.tool === "gitleaks" && f.ruleId !== "GL-005") {
    const m = rawLine.match(/^(\s*)([A-Za-z_][\w]*)\s*=\s*(["'])([^"']{6,})\3\s*$/)
    if (m) {
      const varName = m[2]
      const indent = m[1]
      const edits = [{ filePath: f.filePath, oldCode: rawLine, newCode: `${indent}${varName} = os.environ["${varName}"]` }]
      const imp = ensureImport("import os")
      if (imp) edits.unshift(imp)
      return mk(
        edits,
        `Moves the hardcoded ${varName} literal out of source into an environment lookup (os.environ), removing the credential from the repository while keeping runtime behavior configurable. Deployments must provision the variable.`,
        "Rotate the exposed credential before merging — the value remains in git history.",
      )
    }
    return null
  }

  // ---- weak crypto
  if (f.ruleId === "B-324") {
    const newLine = rawLine.replace(/hashlib\.(md5|sha1)\(/, "hashlib.sha256(")
    if (newLine !== rawLine) {
      return single(newLine, "Replaces the broken hash function with SHA-256, restoring collision resistance.", "Digest values change length/format; verify no storage assumes 32-char hex.")
    }
    return null
  }

  // ---- TLS verification disabled
  if (f.ruleId === "B-113") {
    const newLine = rawLine.replace(/,\s*verify\s*=\s*False|verify\s*=\s*False\s*,\s*/, "")
    if (newLine !== rawLine) {
      return single(newLine, "Removes verify=False so the TLS peer certificate is validated with the default trust store.", "Legacy endpoints with self-signed certificates will fail until a CA bundle is provided.")
    }
    return null
  }

  // ---- debug mode
  if (f.ruleId === "B-501") {
    const newLine = rawLine.replace(/debug\s*=\s*True/i, "debug=False")
    if (newLine !== rawLine) {
      return single(newLine, "Disables the interactive debugger, removing the browser-driven code execution path.", "Debugging must be re-enabled through a local-only flag.")
    }
    return null
  }

  // ---- tempfile.mktemp
  if (f.ruleId === "B-201") {
    const newLine = rawLine.replace(/tempfile\.mktemp\(([^)]*)\)/, "tempfile.NamedTemporaryFile($1, delete=False).name")
    if (newLine !== rawLine) {
      return single(newLine, "Replaces the racy mktemp with NamedTemporaryFile so the path is created securely.", "Caller should remove the file when done.")
    }
    return null
  }

  // ---- unsafe yaml.load
  if (f.ruleId === "B-506") {
    const newLine = rawLine.replace(/yaml\.load\s*\(/, "yaml.safe_load(")
    if (newLine !== rawLine) {
      return single(newLine, "Switches to yaml.safe_load, which cannot construct arbitrary Python objects.", "YAML relying on custom tags will need explicit loaders.")
    }
    return null
  }

  // ---- swallowed exception
  if (f.ruleId === "B-110") {
    const idx = Math.max(0, file.lines.indexOf(rawLine))
    const exceptLine = file.lines[idx]
    const passIdx = file.lines[idx + 1]?.trim() === "pass" ? idx + 1 : idx + 2
    const passLine = file.lines[passIdx]
    if (!exceptLine || !passLine) return null
    const indent = exceptLine.match(/^(\s*)/)?.[1] ?? ""
    const oldCode = `${exceptLine}\n${passLine}`
    const newCode = `${indent}except Exception as exc:\n${indent}    logging.getLogger(__name__).warning("operation failed: %s", exc)`
    const edits: StructuredEdit[] = [{ filePath: f.filePath, oldCode, newCode }]
    const imp = ensureImport("import logging")
    if (imp) edits.unshift(imp)
    return mk(edits, "Logs the swallowed exception instead of discarding it, so failures surface in monitoring.", "Behavior changes only in the failure path.")
  }

  // ---- non-cryptographic random for security values
  if (f.ruleId === "B-311") {
    const newLine = rawLine.replace(/["'][^"']*["']\.join\(\s*random\.choice\([^)]*\)\s*for[^\n]*/i, "secrets.token_hex(16)")
    if (newLine !== rawLine && /secrets\.token_hex/.test(newLine)) {
      const edits: StructuredEdit[] = [{ filePath: f.filePath, oldCode: rawLine, newCode: newLine }]
      const imp = ensureImport("import secrets")
      if (imp) edits.unshift(imp)
      return mk(edits, "Replaces the predictable PRNG token with secrets.token_hex, which uses the OS CSPRNG.", "Existing tokens are invalid after deploy; users must re-authenticate.")
    }
    return null
  }

  // ---- SQL injection family
  if (f.category === "sql-injection") {
    const patched = parameterizeSql(rawLine)
    if (patched) {
      return single(patched, "Converts the dynamically-built SQL into a parameterized query with placeholders, so values cannot alter statement semantics.", "Query plans remain equivalent; verify ORM/logging layers that parse SQL text.")
    }
    return null
  }

  // ---- command injection
  if (f.category === "command-injection") {
    const patched = hardenShellCommand(rawLine)
    if (patched) {
      const edits: StructuredEdit[] = [{ filePath: f.filePath, oldCode: rawLine, newCode: patched }]
      const imp = ensureImport("import subprocess")
      if (imp && /subprocess\.run/.test(patched) && !new RegExp("^import\\s+subprocess\\b", "m").test(file.content)) edits.unshift(imp)
      return mk(edits, "Passes the command as an argument list with shell semantics removed, so untrusted fragments cannot inject shell metacharacters.", "Shell redirection/operator behavior is dropped; redirect via language APIs if needed.")
    }
    return null
  }

  // ---- vulnerable dependency pin
  if (f.tool === "pip-audit" && f.cve) {
    const fix = fixVersionFor(f.cve)
    const m = rawLine.match(/^([A-Za-z0-9_.-]+)\s*==\s*([0-9][\w.\-]*)\s*$/)
    if (fix && m) {
      return single(rawLine.replace(m[0], `${m[1]}==${fix}`), `Upgrades ${m[1]} ${m[2]} → ${fix}, which contains the fix for ${f.cve}.`, "Run the dependency compatibility check in CI after merge.")
    }
    return null
  }

  // categories without a safe deterministic template require human design
  return null
}

/**
 * Locate the finding's line in the *current* snapshot. Earlier verified patches in the
 * same run may have shifted line numbers, so the evidence content is the source of truth.
 * Evidence lines carry their original line numbers; the entry matching the finding's own
 * line is the target — context lines around it are not.
 */
function resolveTargetLine(file: RepoFile, f: { line: number; evidence: string }): string {
  const stored = file.lines[f.line - 1] ?? ""
  const entries = f.evidence
    .split("\n")
    .map((l) => {
      const m = l.match(/^(\d+)\t(.*)$/)
      return m ? { lineNo: parseInt(m[1], 10), content: m[2] } : null
    })
    .filter(Boolean) as { lineNo: number; content: string }[]
  if (entries.length === 0) return stored
  const own = entries.find((e) => e.lineNo === f.line)
  const probe =
    own ??
    entries.reduce((best, e) => (Math.abs(e.lineNo - f.line) < Math.abs(best.lineNo - f.line) ? e : best), entries[0])
  if (stored.trim() === probe.content.trim()) return stored
  // drifted: the same content now lives elsewhere in the current snapshot
  const hit = file.lines.find((l) => l.trim() === probe.content.trim())
  return hit ?? stored
}

/** f-string SQL -> parameterized query (single statement on one line). */
function parameterizeSql(line: string): string | null {
  // pattern: execute(f"...{a}...")
  const fm = line.match(/^(\s*.*?execute\()f(["'])([\s\S]*?)\2(.*)$/)
  if (fm) {
    const [, prefix, quote, sql, tail] = fm
    const params: string[] = []
    let newSql = sql.replace(/(['"])%\{(\w+)\}%\1/g, (_m, q: string, v: string) => {
      params.push(`f${q}%{${v}}%${q}`)
      return "?"
    })
    newSql = newSql.replace(/\{(\w+)\}/g, (_m, v: string) => {
      params.push(v)
      return "?"
    })
    if (params.length === 0) return null
    const q = quote === "'" ? `"${newSql.replace(/"/g, '\\"')}"` : `'${newSql}'`
    return `${prefix}${q}, (${params.join(", ")})${tail}`
  }
  // pattern: execute("LITERAL" + str(var))
  const cm = line.match(/execute\(\s*(["'])([\s\S]*?)\1\s*\+\s*str\((\w+)\)\s*\)/)
  if (cm) {
    const [, quote, literal, v] = cm
    const seg = /[\s(=<>~*-]$/.test(literal) ? `${literal}?` : `${literal} ?`
    const q = quote === "'" ? `'${seg}'` : `"${seg}"`
    return line.replace(cm[0], `execute(${q}, (${v},))`)
  }
  // pattern: execute("LITERAL %s..." % var)
  const pm = line.match(/execute\(\s*(["'])([\s\S]*?)\1\s*%\s*(\w+)\s*\)/)
  if (pm) {
    const [, quote, literal, v] = pm
    if (!literal.includes("%")) return null
    const seg = literal.replace(/%s/g, "?")
    const q = quote === "'" ? `'${seg}'` : `"${seg}"`
    return line.replace(pm[0], `execute(${q}, (${v},))`)
  }
  return null
}

/** shell command with interpolation -> argument list without shell. */
function hardenShellCommand(line: string): string | null {
  const indent = line.match(/^\s*/)?.[0] ?? ""
  // subprocess.X(f"cmd {a} {b}", ...) -> subprocess.X([...], ...)
  const fm = line.match(/subprocess\.(\w+)\(\s*f(["'])([\s\S]*?)\2([\s\S]*?)\)$/)
  if (fm) {
    const [, fn, _quote, cmd, rest] = fm
    const items: string[] = []
    const tokens = cmd.split(/(\{\w+\})/g)
    for (const t of tokens) {
      if (!t) continue
      if (/^\{\w+\}$/.test(t)) {
        items.push(t.slice(1, -1))
      } else {
        for (const w of t.split(/\s+/).filter(Boolean)) items.push(JSON.stringify(w))
      }
    }
    const restClean = rest.replace(/,\s*shell\s*=\s*True|shell\s*=\s*True\s*,?\s*/g, "")
    return `${indent}subprocess.${fn}([${items.join(", ")}]${restClean.replace(/^,\s*/, ", ").replace(/\s+/g, " ")})`
  }
  // os.system("LITERAL" + var) / subprocess.X("LITERAL" + var, shell=True)
  const cm = line.match(/(os\.system|subprocess\.\w+)\(\s*(["'])([\s\S]*?)\2\s*\+\s*(\w+)\s*(,\s*[\s\S]*?)?\)$/)
  if (cm) {
    const [, callee, _q, literal, v, rest] = cm
    if (/[><|;$`&]/.test(literal)) return null // shell semantics cannot be translated safely
    const words = literal.split(/\s+/).filter(Boolean).map((w) => JSON.stringify(w))
    const restClean = (rest ?? "").replace(/,\s*shell\s*=\s*True|shell\s*=\s*True\s*,?\s*/g, "").trim()
    const fn = callee === "os.system" ? "subprocess.run" : callee
    const tail = restClean.startsWith(",") ? ` ${restClean}` : ""
    return `${indent}${fn}([${words.join(", ")}, ${v}]${tail})`
  }
  return null
}
