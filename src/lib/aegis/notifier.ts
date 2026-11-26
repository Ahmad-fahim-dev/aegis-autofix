// Pluggable notifier — any severity upgrade to Critical triggers an immediate
// notification (PRD section 4). Default channel: console + run-log event.
// Additional channels (Slack, PagerDuty, ...) implement the same Notifier
// interface and are selected via the AEGIS_NOTIFIER environment variable.
import type { Severity } from "./types"

export interface CriticalNotification {
  refId: string
  title: string
  filePath: string
  line: number
  fromSeverity: Severity
  reasoning?: string | null
}

export interface Notifier {
  readonly channel: string
  notifyCritical(notification: CriticalNotification): Promise<void>
}

/** Structural type of the engine's event emitter (append-only run log + realtime broadcast). */
export type NotifyEmit = (
  type: string,
  opts?: { stage?: string; level?: "info" | "success" | "warn" | "error"; message?: string; payload?: Record<string, unknown> },
) => Promise<void>

function consoleNotifier(emit: NotifyEmit): Notifier {
  return {
    channel: "console+event-log",
    notifyCritical: async (n) => {
      // channel 1: console (operator-visible in server logs)
      console.error(
        `[aegis:critical] ${n.refId} "${n.title}" @ ${n.filePath}:${n.line} — severity ${n.fromSeverity} -> CRITICAL (immediate notification, same-day SLA)`,
      )
      // channel 2: the immutable run log (replayable audit trail)
      await emit("CRITICAL_ALERT", {
        stage: "TRIAGE",
        level: "error",
        message: `IMMEDIATE NOTIFICATION: ${n.refId} upgraded to Critical (${n.title} @ ${n.filePath}:${n.line})`,
        payload: { refId: n.refId, from: n.fromSeverity, reasoning: n.reasoning ?? null, channel: "console+event-log" },
      })
    },
  }
}

/** Resolve the configured notifier. Unknown channels fall back to the default (fail safe, never silent). */
export function getNotifier(emit: NotifyEmit): Notifier {
  switch (process.env.AEGIS_NOTIFIER) {
    case "console":
    case "":
    case undefined:
      return consoleNotifier(emit)
    default:
      // fail-safe: an unimplemented channel still notifies via console + event log
      return consoleNotifier(emit)
  }
}
