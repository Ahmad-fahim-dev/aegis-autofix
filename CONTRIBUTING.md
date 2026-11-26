# Contributing to AEGIS

Thanks for your interest in making AEGIS better. This document covers setup,
workflow, and the safety invariants every change must preserve.

## Development setup

Requirements: Node 20+ / Bun 1.1+, Python 3.12 (sandbox test gate), SQLite (bundled).

```bash
git clone https://github.com/Ahmad-fahim-dev/aegis-autofix.git
cd aegis-autofix
bun install
cp .env.example .env        # all values optional for local development
mkdir -p db && bun run db:push
bun run dev                 # console on http://localhost:3000
```

Optionally start the realtime event stream (Socket.IO) in a second terminal:

```bash
cd mini-services/aegis-realtime && bun install && bun run dev
```

> **Note** — the vendored Cloudflare `security-audit-skill` (`skills/`) is not
> redistributed in this repository. The in-tree six-phase audit
> (`src/lib/aegis/audit/`) is fully functional without it; `bun run self:audit`
> and the skill validators run only where the skill is present.

## Workflow

1. Fork the repository and create a feature branch from `main`.
2. Keep changes focused — one logical change per pull request.
3. Verify before opening a PR:

   ```bash
   bun run lint          # ESLint (Next.js + TypeScript rules)
   bun run typecheck     # tsc --noEmit
   ```

4. Open the pull request with a clear description: what changed, why, and how
   it was verified. New engine behavior should be demonstrated against the
   bundled fixtures (`sample://vuln-blog`, `sample://clean-service`).

## Code standards

- TypeScript throughout, strict typing, ES modules.
- UI: Tailwind CSS 4 + shadcn/ui components (`src/components/ui`) — prefer
  existing primitives over new dependencies.
- Engine code lives in `src/lib/aegis/` — every stage writes to the event store
  so runs stay replayable.
- Database changes go through `prisma/schema.prisma` (SQLite).
- No secrets in code, logs, or test fixtures — real-looking credentials must be
  clearly fake and confined to `samples/`.

## Safety invariants — never break these

AEGIS is a security tool; regressions here are not ordinary bugs.

1. **PR-only delivery.** The engine never merges and never writes to protected
   branches.
2. **Deterministic ground truth.** The LLM router never decides detection
   truth — only scanners do.
3. **Verified mutations.** Every auto-fix patch passes the sandbox gates
   (exact-match apply, pytest, targeted re-scan, protected-path policy).
4. **Fail-closed redaction.** Secrets are masked before any external model
   call.
5. **Bounded runs.** Budget and wall-clock caps are checked before every
   remediation attempt.

If a change touches any of these paths, call it out explicitly in the PR
description.

## Reporting security issues

Do **not** open public issues for vulnerabilities — follow
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
