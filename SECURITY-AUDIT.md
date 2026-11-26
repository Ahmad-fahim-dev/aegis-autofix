# AEGIS v1.0 — Full Security Audit

**Date**: 2026-11-17 · **Auditor**: Cloudflare security-audit-skill (vendored, `skills/security-audit/`) + senior-engineer human review
**Target**: this repository (working tree) · **Profile**: standard · **Execution policy**: sandboxed-source-and-local-only

---

## 1. Automated six-phase skill audit (run inside this backend)

`bun run self:audit` executes the vendored Cloudflare security-audit-skill against this
project's own source (112 files, 424 coverage units over 18 entry surfaces). Output artifacts:

- `.aegis-audit/self/self-<ts>/REPORT.md` — skill-derived report
- `.aegis-audit/self/self-<ts>/FINDINGS-DETAIL.md` — per-record detail
- `.aegis-audit/self/self-<ts>/findings.json` + `coverage-ledger.json` — **both vendored validators PASS**

## 2. Human triage of the 7 automated records — all refuted

Every confirmed record the deterministic hunters produced cites the *detector's own rule
text*, not executing vulnerable code (the known self-referential limitation of pattern
hunters auditing a scanner codebase):

| # | Record | Verdict | Basis |
|---|--------|---------|-------|
| 1–2 | "Debug mode enabled" @ `audit/hunt.ts:611`, `drivers/bandit.ts:117` | **Refuted** | Cited lines are the B-501 rule *definition* (`test: (l) => /debug\s*=\s*True/i`) and its output template. No Flask runtime exists — AEGIS is Next.js/TypeScript. |
| 3–6 | "Request-derived path reaches file operation" @ `aegis-realtime/index.ts`, `hunt.ts`, `runner.ts`, `sandbox.ts` | **Refuted** | The `path.posix.join("/var/app/uploads", "../../etc/passwd")` occurrences are the auditor's own bounded local-reproduction code (skill methodology §Universal execution safety). The realtime service reads a static relative `.env` — no request-derived component. |
| 7 | "Non-cryptographic RNG for security value" @ `hunt.ts:503` | **Refuted** | Cited line is the weak-randomness *detector regex*, not a generator. |

Per the skill's validation discipline, refuted records carry no severity and are recorded
here rather than in `findings.json`.

## 3. Manual deep audit — every attack surface (senior-engineer review)

| Surface | Control verified | Status |
|---|---|---|
| `POST /api/runs` | zod schema (repoUrl ≤300 chars, mode enum); admission control (MAX_ACTIVE_RUNS=2 → 429); **new** 256 KB stream-level body cap | PASS |
| `PUT /api/settings` | zod-validated budgets/paths; API-key mask reveals provider prefix + length only | PASS |
| `POST /api/escalations/[id]` | action enum + note ≤500; idempotence via OPEN-status check (409) | PASS |
| Repo resolution (`repo.ts`) | `execFile` argument-array clone (no shell metacharacters reachable); strict `https://github.com/<owner>/<repo>` regex; sample allow-list + `startsWith` path confinement; 400-file / 200 KB-per-file / 8 MB-buffer bounds; 120 s clone timeout; cleanup on every outcome | PASS |
| Sandbox verify (`sandbox.ts`) | exact-match unambiguous patch application; `py_compile` gate; rescan; protected-path policy; secret re-binding confined to the apply step; failure context redacted | PASS |
| Realtime bridge (`:3001`) | `x-bridge-token` timing-safe (sha256-digested) compare, fail-closed without token; 512 KB body cap; origin-gate on socket handshakes; subscribe runId validated (string, <64) | PASS |
| Report export (`/api/runs/[id]/report`) | run-id charset check; HTML served as attachment + `X-Content-Type-Options: nosniff`; every scanned-repo byte escaped (`& < >` in text, `<pre>`-closed fences); filename slug sanitized | PASS |
| Secret handling | evidence/LLM-prompt/failure-context all pass `redactText`; masked bindings keep real literals out of model context | PASS |
| LLM egress | Groq key never logged; HEURISTIC fail-safe when absent | PASS |
| Skill-audit integration (new) | `runSkillAudit` writes only under `.aegis-audit/<runId>` (gitignored); validator child processes (`execFile`, 30 s timeout, 512 KB buffer); audit failure degrades the run (warn event), never blocks it | PASS |

## 4. Dependency audit — remediated

`bun audit` before: **99 vulnerabilities (5 critical, 55 high)** → after: **26 (0 critical, 18 high, 7 moderate, 1 low)**.

Actions taken:

- `next` 16.1.3 → **16.4.6** (clears 39 advisories incl. all 4 Next criticals: RCE-in-image-optimization family, `use cache` RCE, SSRF-in-rewrites)
- `zod` 4.0.2 → **4.6.7** (GHSA memory-exhaustion via constrained collections — additionally hardened below)
- `next-auth` **removed** — was completely unused (zero imports); removes 3 advisories incl. 1 critical
- `bun update` across ranges: 148 packages refreshed

Residual 26: dev/build-time transitives only (browserslist stats parsing, babel sourcemap traversal, minimatch/picomatch/brace-expansion glob ReDoS, lodash-via-recharts). None are attacker-reachable — the app performs no glob evaluation of user input, no custom browserslist stats, no `_.template`/`_.unset` on user data (verified absent in recharts' runtime path), and these have no patched releases upstream.

## 5. New hardening from this audit

1. **Stream-level request-body caps** (`src/lib/aegis/http.ts`, wired into every mutating route): Content-Length declared cap *and* read-time byte cap → 413. Defends against any validator-input memory-exhaustion class regardless of library patch level (verified: 300 KB body → 413; lying Content-Length 999999999 → 413).
2. **Skill-integration blast-radius controls**: audit artifacts confined to `.aegis-audit/` (gitignored); integration failure is a warn-level degradation.

## 6. Prior hardening verified present (runs 1–2)

Admission control (429 at capacity) · findings cap 2 000/run with visible truncation event ·
run-id charset gate · clone retry bound (2) · budget ceilings with escalation trail ·
protected-path policy gate · redaction at every persistence/egress point · bridge
fail-closed · origin-gated sockets · nosniff attachment HTML export.

## 7. Coverage statement

One standard-profile pass + dependency sweep + surface-by-surface manual review. Deep
logic classes (novel business-logic chains, multi-step exploit composition) remain
human-audit territory — this report makes no completeness claim beyond the units above.
Re-run any time: `bun run self:audit`.
