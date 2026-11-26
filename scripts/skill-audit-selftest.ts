// Test-time execution of the vendored Cloudflare security-audit-skill inside AEGIS.
//
// "When tests run, the skill also runs": `bun run test` invokes this self-test,
// which executes the full six-phase audit workflow (reconnaissance -> coverage-led
// hunting -> candidate validation -> structured output -> independent verification
// -> target-neutral report) on the bundled vuln-blog fixture and asserts the
// vendored Cloudflare validators gate the output to PASS.
import { promises as fs } from "fs"
import path from "path"
import { runSkillAudit } from "../src/lib/aegis/audit/runner"
import type { RepoFile } from "../src/lib/aegis/types"

const FIXTURE = "vuln-blog"
const TEXT_EXT = /\.(py|txt|toml|md|json|ya?ml|cfg|ini|ts|tsx|js|cjs|mjs|html|env|gitignore)$/i

async function loadFixture(name: string): Promise<RepoFile[]> {
  const root = path.resolve(process.cwd(), "samples", name)
  const files: RepoFile[] = []
  const walk = async (dir: string, rel = ""): Promise<void> => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "__pycache__" || entry.name.startsWith(".#")) continue
      const abs = path.join(dir, entry.name)
      const relPath = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) await walk(abs, relPath)
      else if (TEXT_EXT.test(entry.name) || entry.name === ".env" || entry.name === ".gitignore") {
        const stat = await fs.stat(abs).catch(() => null)
        if (!stat || stat.size > 200_000) continue
        const content = await fs.readFile(abs, "utf8").catch(() => "")
        if (content.includes("\u0000")) continue // binary guard
        files.push({ path: relPath, content, lines: content.split("\n") })
      }
    }
  }
  await walk(root)
  return files
}

function finish(code: number, summary: string): never {
  console.log(summary)
  process.exit(code)
}

const files = await loadFixture(FIXTURE)
if (files.length === 0) finish(1, `FAIL: fixture "${FIXTURE}" could not be loaded from samples/`)

const runId = `selftest-${Date.now()}`
const result = await runSkillAudit(files, {
  repoName: FIXTURE,
  sourceRef: "selftest",
  runId,
  outputBase: path.resolve(process.cwd(), ".aegis-audit", "selftest"),
})

const failures: string[] = []
if (!result.ok) failures.push(`audit run did not complete: ${result.error ?? "unknown error"}`)
for (const v of result.validators) {
  if (!v.pass) failures.push(`${v.tool} validator FAILED: ${v.output.slice(0, 300)}`)
}
if (result.stats.confirmed < 1) failures.push("no confirmed findings — hunters produced no validated candidates")
if (result.pipelineFindings.length < 1) failures.push("no pipeline findings projected from confirmed records")
if (result.ledgerStats.total < 1) failures.push("coverage ledger is empty — reconnaissance seeded no units")

if (result.outputDir) {
  const report = await fs.readFile(path.join(result.outputDir, "REPORT.md"), "utf8").catch(() => null)
  if (!report) failures.push("REPORT.md artifact was not written")
  const findingsJson = await fs.readFile(path.join(result.outputDir, "findings.json"), "utf8").catch(() => null)
  if (!findingsJson) failures.push("findings.json artifact was not written")
  const ledgerJson = await fs.readFile(path.join(result.outputDir, "coverage-ledger.json"), "utf8").catch(() => null)
  if (!ledgerJson) failures.push("coverage-ledger.json artifact was not written")
}

if (failures.length > 0) {
  finish(1, `SKILL AUDIT SELF-TEST FAILED:\n- ${failures.join("\n- ")}`)
}

finish(
  0,
  [
    "SKILL AUDIT SELF-TEST PASSED — the vendored Cloudflare security-audit-skill ran its six-phase workflow end-to-end",
    `  fixture:            ${FIXTURE} (${files.length} files)`,
    `  coverage units:     ${result.ledgerStats.total} (${result.ledgerStats.candidate} with candidates)`,
    `  records:            ${result.stats.confirmed} confirmed / ${result.stats.needsValidation} needs-validation / ${result.stats.rejected} rejected`,
    `  pipeline findings:  ${result.pipelineFindings.length} projected into the unified AEGIS finding schema`,
    `  validators:         ${result.validators.map((v) => `${v.tool}=${v.pass ? "PASS" : "FAIL"}`).join(", ")}`,
    `  artifacts:          ${result.outputDir}`,
  ].join("\n"),
)
