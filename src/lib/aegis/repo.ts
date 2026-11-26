// Repo resolution: GitHub shallow clone at a pinned commit (bounded retries) or sample fixture
import { execFile } from "child_process"
import { createHash } from "crypto"
import { promises as fs } from "fs"
import path from "path"
import { isSkippedPath } from "./drivers"
import type { RepoFile } from "./types"

const MAX_FILES = 400
const MAX_FILE_BYTES = 200_000
const TEXT_EXT = /\.(py|txt|toml|cfg|ini|yaml|yml|json|env|md|sh|html|js|ts|rb|go|java|sql)$/i

export interface ResolvedRepo {
  source: "GITHUB" | "SAMPLE"
  localPath: string
  commitSha: string
  repoName: string
  cleanup: () => Promise<void>
}

function exec(cmd: string, args: string[], opts: { cwd?: string; timeoutMs?: number } = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const t = setTimeout(() => child.kill(), opts.timeoutMs ?? 90_000)
    const child = execFile(cmd, args, { cwd: opts.cwd, maxBuffer: 1024 * 1024 * 8 }, (err, stdout, stderr) => {
      clearTimeout(t)
      resolve({ code: err ? (err as { code?: number }).code ?? 1 : 0, stdout: String(stdout), stderr: String(stderr) })
    })
  })
}

async function dirFiles(root: string, base: string): Promise<RepoFile[]> {
  const out: RepoFile[] = []
  const walk = async (dir: string) => {
    if (out.length >= MAX_FILES) return
    let entries: import("fs").Dirent[]
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return
      const rel = path.relative(base, path.join(dir, e.name))
      if (isSkippedPath(rel)) continue
      if (e.isDirectory()) {
        await walk(path.join(dir, e.name))
      } else if (e.isFile() && TEXT_EXT.test(e.name)) {
        try {
          const stat = await fs.stat(path.join(dir, e.name))
          if (stat.size > MAX_FILE_BYTES) continue
          const content = await fs.readFile(path.join(dir, e.name), "utf8")
          out.push({ path: rel.split(path.sep).join("/"), content, lines: content.split("\n") })
        } catch {
          /* ignore unreadable */
        }
      }
    }
  }
  await walk(root)
  out.sort((a, b) => a.path.localeCompare(b.path))
  return out
}

export async function loadRepoFiles(localPath: string): Promise<RepoFile[]> {
  return dirFiles(localPath, localPath)
}

function syntheticCommit(files: RepoFile[]): string {
  const h = createHash("sha256")
  for (const f of files) h.update(f.path).update(f.content)
  return h.digest("hex").slice(0, 12)
}

export interface ResolveResult {
  ok: boolean
  repo?: ResolvedRepo
  files: RepoFile[]
  error?: string
  guidance?: string
}

// Security hardening (audit run-1): sample fixture allow-list — the sample:// name may
// only be one of the bundled fixtures, and the resolved path must stay a direct child
// of the samples root (no traversal, no host-root escape).
const SAMPLE_ALLOWLIST = ["vuln-blog", "clean-service"]

/** Resolve a repo URL: sample fixtures resolve directly; GitHub URLs shallow-clone with bounded retries. */
export async function resolveRepo(input: RepoInput): Promise<ResolveResult> {
  const { url } = input

  if (url.startsWith("sample://")) {
    const name = url.replace("sample://", "")
    if (!SAMPLE_ALLOWLIST.includes(name)) {
      return {
        ok: false,
        files: [],
        error: `Sample repo "${name}" not found.`,
        guidance: "Pick one of the bundled sample repos (vuln-blog, clean-service) or provide a GitHub URL.",
      }
    }
    const samplesRoot = path.resolve(process.cwd(), "samples")
    const localPath = path.resolve(samplesRoot, name)
    if (!localPath.startsWith(samplesRoot + path.sep)) {
      return {
        ok: false,
        files: [],
        error: "Invalid sample path.",
        guidance: "Pick a bundled sample repo or provide a GitHub URL.",
      }
    }
    try {
      const stat = await fs.stat(localPath)
      if (!stat.isDirectory()) throw new Error("not a directory")
      const files = await loadRepoFiles(localPath)
      if (files.length === 0) throw new Error("no scannable files")
      return {
        ok: true,
        files,
        repo: {
          source: "SAMPLE",
          localPath,
          commitSha: syntheticCommit(files),
          repoName: name,
          cleanup: async () => {},
        },
      }
    } catch {
      return {
        ok: false,
        files: [],
        error: `Sample repo "${name}" not found.`,
        guidance: "Pick one of the bundled sample repos (vuln-blog, clean-service) or provide a GitHub URL.",
      }
    }
  }

  // GitHub URL
  const normalized = url.trim().replace(/\.git$/, "")
  const m = normalized.match(/^https:\/\/(?:www\.)?github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/?$/)
  if (!m) {
    return {
      ok: false,
      files: [],
      error: "Not a valid GitHub repository URL.",
      guidance: "Expected https://github.com/<owner>/<repo>. Re-enter the URL, or use a bundled sample repo.",
    }
  }
  const fullName = m[1]
  const repoName = fullName.split("/")[1]

  // bounded retries with guidance (PRD workflow step 2)
  let lastErr = ""
  for (let attempt = 1; attempt <= 2; attempt++) {
    const target = path.join("/tmp", "aegis-repos", `${repoName}-${Date.now()}-${attempt}`)
    try {
      await fs.mkdir(path.dirname(target), { recursive: true })
    } catch {
      /* exists */
    }
    const res = await exec(
      "git",
      // --filter blob:limit bounds the working tree size on disk (audit run-1: run admission)
      ["clone", "--depth", "1", "--filter", "blob:limit=1m", `https://github.com/${fullName}.git`, target],
      { timeoutMs: 120_000 },
    )
    if (res.code === 0) {
      const shaRes = await exec("git", ["rev-parse", "HEAD"], { cwd: target, timeoutMs: 15_000 })
      const files = await loadRepoFiles(target)
      return {
        ok: true,
        files,
        repo: {
          source: "GITHUB",
          localPath: target,
          commitSha: shaRes.stdout.trim().slice(0, 12) || "unknown",
          repoName: fullName,
          cleanup: async () => {
            await fs.rm(target, { recursive: true, force: true }).catch(() => {})
          },
        },
      }
    }
    lastErr = res.stderr.split("\n").filter(Boolean).slice(-2).join(" ")
    await fs.rm(target, { recursive: true, force: true }).catch(() => {})
  }

  return {
    ok: false,
    files: [],
    error: `Repository not found or unreachable: ${lastErr || "clone failed"}`,
    guidance:
      "Verify the URL is correct and the repo is public (or that the deployment has read credentials). Bounded retries exhausted — run aborted per policy. Bundled sample repos are available for evaluation.",
  }
}

export interface RepoInput {
  url: string
}
