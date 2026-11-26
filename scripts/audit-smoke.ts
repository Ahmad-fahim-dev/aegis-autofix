// Smoke test: run the full security-audit-skill workflow against a fixture repo
import { loadRepoFiles } from "../src/lib/aegis/repo"
import { runSkillAudit } from "../src/lib/aegis/audit/runner"

const target = process.argv[2] ?? "samples/vuln-blog"
const files = await loadRepoFiles(target)
console.log(`loaded ${files.length} files from ${target}`)

const result = await runSkillAudit(files, {
  repoName: target,
  sourceRef: "smoke",
  runId: `smoke-${Date.now()}`,
  outputBase: "/tmp/aegis-audit-smoke",
})

console.log("ok:", result.ok, "error:", result.error ?? "-")
console.log("ledger:", result.ledgerStats)
console.log("stats:", result.stats)
for (const v of result.validators) console.log(`validator ${v.tool}: ${v.pass ? "PASS" : "FAIL"} — ${v.output}`)
console.log("pipeline findings:")
for (const f of result.pipelineFindings) console.log(`  [${f.severity}] ${f.ruleId} ${f.filePath}:${f.line} — ${f.title}`)
for (const e of result.events) console.log(`event ${e.type}: ${e.message}`)
process.exit(result.ok && result.validators.every((v) => v.pass) ? 0 : 1)
