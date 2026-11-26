# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x (`main`) | Yes |

## Reporting a vulnerability

We take the security of AEGIS seriously. If you believe you have found a
security vulnerability, please report it privately:

- **GitHub Security Advisories** — open a private report via the
  *Security → Report a vulnerability* tab of this repository.
- Or email the maintainer directly (see the GitHub profile).

Please include:

1. A description of the issue and its impact.
2. Steps or a proof of concept to reproduce it.
3. Affected version / commit.

**Do not open a public issue for security vulnerabilities.**

You will receive an acknowledgement within 72 hours. We aim to validate,
fix, and coordinate disclosure within 90 days. Please avoid public
disclosure until a fix is released.

## Scope notes

AEGIS intentionally processes untrusted repository code. The following are
treated as security-relevant surfaces:

- The sandbox verification path (`src/lib/aegis/sandbox.ts`) — escapes,
  credential leaks, or gate bypasses.
- Repo resolution and cloning (`src/lib/aegis/repo.ts`) — command injection,
  path traversal, resource exhaustion.
- The REST API (`src/app/api/`) — authentication bypass, request smuggling,
  unbounded payloads.
- Secret redaction (`src/lib/aegis/redact.ts`) — leaks of masked material.
- The realtime bridge (`mini-services/aegis-realtime/`) — broadcast
  forgery or token bypass.

## Security model

The project's own audit trail — a six-phase automated audit plus manual triage
of every attack surface — is published in
[SECURITY-AUDIT.md](SECURITY-AUDIT.md). The operator-facing safety guarantees
are summarized in the [README](README.md#safety-model).
