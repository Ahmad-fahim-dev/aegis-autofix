// AEGIS self-audit — runs the vendored Cloudflare security-audit-skill against
// THIS project's own source tree. The skill audits AEGIS with the same six-phase
// workflow it applies to any target repository loaded by the engine:
//   1 reconnaissance          4 structured output (validators gate it)
//   2 coverage-led hunting    5 independent record verification
//   3 candidate validation    6 target-neutral report
// Output lands in .aegis-audit/self/ and is surfaced as the project's own
// security audit record. Re-run any time with: bun run self:audit
import { promises as fs } from "fs"
import path from "path"
import { runSkillAudit } from "../src/lib/aegis/audit/runner"
import type { RepoFile } from "../src/lib/aegis/types"

// Bounded allowlist of AEGIS's own audit-relevant source (no vendored upstream
// skill files, no node_modules, no build output, no fixture samples).
const INCLUDE_DIRS = ["src", "mini-services", "prisma", "scripts"]
const INCLUDE_FILES = ["package.json", "next.config.ts", "tsconfig.json", "Caddyfile"]
const SKIP_DIRS = new Set([".git", "__pycache__", "node_modules", ".next", ".turbo", "skills", "samples", ".aegis-audit", "db", "tool-results", "public", "agent-ctx"])
const TEXT_EXT = /\.(ts|tsx|js|cjs|mjs|json|prisma|md|toml|ya?ml|txt|css|html|env|gitignore)$/i

async function loadSelf(): Promise<RepoFile[]> {
  const files: RepoFile[] = []
  const walk = async (dir: string, rel = ""): Promise<void> => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true }).catch(() => [])) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".#")) continue
      const abs = path.join(dir, entry.name)
      const relPath = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) await walk(abs, relPath)
      else if (TEXT_EXT.test(entry.name) || entry.name === ".env" || entry.name === ".gitignore" || entry.name === "Caddyfile") {
        const stat = await fs.stat(abs).catch(() => null)
        if (!stat || stat.size > 300_000) continue
        const content = await fs.readFile(abs, "utf8").catch(() => "")
        if (content.includes("\u0000")) continue
        files.push({ path: relPath, content, lines: content.split("\n") })
      }
    }
  }
  for (const dir of INCLUDE_DIRS) await walk(path.resolve(process.cwd(), dir))
  for (const file of INCLUDE_FILES) {
    const abs = path.resolve(process.cwd(), file)
    const content = await fs.readFile(abs, "utf8").catch(() => null)
    if (content != null && !content.includes("\u0000")) files.push({ path: file, content, lines: content.split("\n") })
  }
  return files
}

function finish(code: number, summary: string): never {
  console.log(summary)
  process.exit(code)
}

const files = await loadSelf()
if (files.length === 0) finish(1, "FAIL: AEGIS self-audit could not load any source files")

const runId = `self-${new Date().toISOString().replace(/[:.]/g, "-")}`
const result = await runSkillAudit(files, {
  repoName: "aegis",
  sourceRef: "working-tree",
  runId,
  outputBase: path.resolve(process.cwd(), ".aegis-audit", "self"),
})

if (!result.ok) finish(1, `SELF-AUDIT FAILED: ${result.error ?? "unknown error"}`)

finish(
  0,
  [
    "AEGIS SELF-AUDIT COMPLETE — the vendored Cloudflare security-audit-skill audited this project's own source",
    `  files under audit:  ${files.length}`,
    `  coverage units:    ${result.ledgerStats.total} (${result.ledgerStats.candidate} with candidates)`,
    `  records:            ${result.stats.confirmed} confirmed / ${result.stats.needsValidation} needs-validation / ${result.stats.rejected} rejected`,
    `  pipeline findings: ${result.pipelineFindings.length}`,
    `  validators:        ${result.validators.map((v) => `${v.tool}=${v.pass ? "PASS" : "FAIL"}`).join(", ")}`,
    `  report:            ${result.reports?.report}`,
    `  detail:            ${result.reports?.detail}`,
    `  needs-validation:  ${result.reports?.needsValidation}`,
  ].join("\n"),
)
