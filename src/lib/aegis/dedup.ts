// Dedup across tools: findings on the same file+line from multiple drivers are one issue
import type { RawFinding, ScanTool, Severity } from "./types"

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

export interface MergedFinding {
  refId: string
  fingerprint: string
  tools: ScanTool[]
  ruleIds: string[]
  primary: RawFinding
  sources: RawFinding[]
}

export function dedupFindings(raw: RawFinding[]): MergedFinding[] {
  const groups = new Map<string, RawFinding[]>()
  for (const f of raw) {
    const key = `${f.filePath}:${f.line}`
    const arr = groups.get(key) ?? []
    arr.push(f)
    groups.set(key, arr)
  }
  const merged: MergedFinding[] = []
  let n = 0
  for (const [key, sources] of groups) {
    const sorted = [...sources].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
    const primary = sorted[0]
    const tools = [...new Set(sources.map((s) => s.tool))] as ScanTool[]
    const ruleIds = sources.map((s) => s.ruleId)
    merged.push({
      refId: `F${String(++n).padStart(3, "0")}`,
      fingerprint: key,
      tools,
      ruleIds,
      primary,
      sources,
    })
  }
  // deterministic order: severity then path
  merged.sort(
    (a, b) =>
      SEVERITY_ORDER[b.primary.severity] - SEVERITY_ORDER[a.primary.severity] ||
      a.primary.filePath.localeCompare(b.primary.filePath) ||
      a.primary.line - b.primary.line,
  )
  return merged
}
