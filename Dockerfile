# AEGIS v1.0 — patch-verification sandbox image (build tag: aegis-sandbox:1.0.0)
#
# The PRD requires patch verification to run in an "ephemeral, network-isolated,
# credential-free Docker sandbox" that executes pytest. This image is only half
# of that contract: it ships a minimal, PINNED Python test toolchain and runs as
# a non-root user. The isolation properties (no network, read-only rootfs, no
# new privileges, pid/cpu/memory ceilings) are RUNTIME flags and cannot be
# baked into an image — the engine must launch it exactly like this:
#
#   docker run --rm --network none --cpus 1 --memory 512m --read-only \
#     --tmpfs /sandbox:rw,size=64m,exec --pids-limit 64 \
#     --security-opt no-new-privileges \
#     -v <patched-repo>:/sandbox/repo \
#     aegis-sandbox:1.0.0 pytest /sandbox/repo -q --no-header
#
# Flag rationale (why each one is required for the security properties):
#   --network none            no exfiltration channel; patch verification needs zero network
#   --read-only               the image layers are immutable; nothing persists after the attempt
#   --tmpfs /sandbox:rw,...   the ONLY writable surface — the patched tree + pyc artifacts, capped at 64m
#   --pids-limit 64           fork-bomb ceiling inside the gate
#   --cpus 1 / --memory 512m  a single verification attempt cannot starve the host
#   --security-opt no-new-privileges  setuid binaries in the base image gain nothing
#   --rm                      ephemeral by construction — no container, no fs, no evidence left behind
#
# No HEALTHCHECK on purpose: the container is network-isolated and --rm-scoped,
# so a health probe has nothing to probe and nowhere to report.
#
# Toolchain (pinned, pip --no-cache-dir):
#   pytest     — the regression-test gate itself
#   bandit     — targeted re-scan of patched files (offline rules)
#   semgrep    — targeted re-scan of patched files (offline rules)
#   pip-audit  — dependency re-check; in network-isolated mode it must be fed an
#                offline OSV export by the host runner (see comment below)
#
#   gitleaks is NOT installed here — honest limitation: gitleaks ships as a
#   pre-fetched release binary (it is not on PyPI), so a COPY of it into this
#   image is not possible in this build context. It is provided by the HOST
#   RUNNER outside the sandbox: the engine runs the gitleaks pass on the host
#   and mounts only static files into the container. If a deployment wants the
#   secret re-scan inside the sandbox too, pre-fetch the binary and add a layer:
#   COPY --from=gitleaks-bin /usr/local/bin/gitleaks /usr/local/bin/gitleaks
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pinned scanner + test tooling — exact versions, no cache kept, no build deps kept.
RUN pip install --no-cache-dir \
      bandit==1.7.9 \
      semgrep==1.52.0 \
      pip-audit==2.6.1 \
      pytest==8.3.4

# Non-root runtime identity: uid 10001, no login shell needed, no home data.
RUN useradd --uid 10001 --system aegis

# /sandbox is a tmpfs mount point at run time (see the run flags above);
# the patched repo is mounted read-write at /sandbox/repo by the engine.
WORKDIR /sandbox
USER aegis

CMD ["pytest", "-q", "--no-header", "/sandbox/repo"]
