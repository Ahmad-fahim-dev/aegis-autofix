// Policy & budget guard — per-run cost and wall-clock caps, 3-attempt limit, path gates
import type { RunBudgets } from "./types"

export interface BudgetState {
  spentUsd: number
  startedAtMs: number
  budgets: RunBudgets
}

export function initBudgetState(budgets: RunBudgets): BudgetState {
  return { spentUsd: 0, startedAtMs: Date.now(), budgets }
}

export function addCost(state: BudgetState, costUsd: number): void {
  state.spentUsd += costUsd
}

/** Budgets are checked before every attempt, so runs always terminate (PRD §3). */
export function budgetCheck(state: BudgetState, attemptsUsed: number): { allowed: boolean; reason?: string } {
  if (attemptsUsed >= state.budgets.maxAttemptsPerFinding) {
    return { allowed: false, reason: "MAX_ATTEMPTS" }
  }
  if (state.spentUsd >= state.budgets.costCeilingUsd) {
    return { allowed: false, reason: "BUDGET_EXHAUSTED" }
  }
  const elapsedMin = (Date.now() - state.startedAtMs) / 60000
  if (elapsedMin >= state.budgets.wallClockCeilingMin) {
    return { allowed: false, reason: "BUDGET_EXHAUSTED" }
  }
  return { allowed: true }
}

/** Path gates: auth-critical code is never auto-patched without human review (PRD §3). */
export function isProtectedPath(filePath: string, protectedPaths: string[]): boolean {
  return protectedPaths.some((pattern) => {
    if (pattern.includes("**/")) {
      const suffix = pattern.replace(/\*\*\//g, "")
      if (suffix.endsWith("/**")) {
        const dir = suffix.replace(/\/\*\*$/, "")
        return filePath.includes(`/${dir}/`) || filePath.startsWith(`${dir}/`)
      }
      return filePath === suffix || filePath.endsWith(`/${suffix}`)
    }
    return filePath === pattern
  })
}
