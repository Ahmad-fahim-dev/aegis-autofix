// Model-agnostic LLM router — Groq (OpenAI-compatible) primary, the built-in
// platform LLM bridge (z-ai-web-dev-sdk, server-side only) second, deterministic
// fallback last. JSON-schema output contracts; malformed response = retry, then
// degrade to the next provider, then to the fallback (PRD §5 model layer).
import type { LlmResult, LlmUsage } from "./types"

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

// Approximate USD per 1M tokens (public Groq pricing, used for telemetry estimates)
const PRICING: Record<string, { in: number; out: number }> = {
  "llama-3.3-70b-versatile": { in: 0.59, out: 0.79 },
  "llama-3.1-8b-instant": { in: 0.05, out: 0.08 },
  "openai/gpt-oss-120b": { in: 0.15, out: 0.6 },
  "openai/gpt-oss-20b": { in: 0.1, out: 0.24 },
  "qwen/qwen3-32b": { in: 0.29, out: 0.59 },
  "moonshotai/kimi-k2-instruct": { in: 0.55, out: 2.5 },
  "deepseek-r1-distill-llama-70b": { in: 0.75, out: 0.99 },
  "meta-llama/llama-4-scout-17b-16e-instruct": { in: 0.11, out: 0.34 },
  "meta-llama/llama-4-maverick-17b-128e-instruct": { in: 0.2, out: 0.6 },
}

export const GROQ_MODELS = Object.keys(PRICING)

export function estimateCostUsd(model: string, usage: LlmUsage): number {
  const p = PRICING[model] ?? { in: 0.59, out: 0.79 }
  return (usage.promptTokens / 1e6) * p.in + (usage.completionTokens / 1e6) * p.out
}

export function estimateUsageFromText(prompt: string, completion: string): LlmUsage {
  return {
    promptTokens: Math.ceil(prompt.length / 4),
    completionTokens: Math.ceil(completion.length / 4),
    latencyMs: 0,
  }
}

interface ChatOptions {
  apiKey: string
  model: string
  system: string
  user: string
  maxTokens?: number
  timeoutMs?: number
}

interface RawChatResult {
  ok: boolean
  content?: string
  usage: LlmUsage
  error?: string
  model?: string
}

async function chatCompletion(opts: ChatOptions): Promise<RawChatResult> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 45000)
  const started = Date.now()
  try {
    const res = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${opts.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: opts.model,
        messages: [
          { role: "system", content: opts.system },
          { role: "user", content: opts.user },
        ],
        temperature: 0.2,
        max_tokens: opts.maxTokens ?? 3000,
        response_format: { type: "json_object" },
      }),
      signal: controller.signal,
    })
    if (!res.ok) {
      const body = await res.text().catch(() => "")
      return { ok: false, usage: { promptTokens: 0, completionTokens: 0, latencyMs: Date.now() - started }, error: `HTTP ${res.status} ${body.slice(0, 180)}` }
    }
    const json = (await res.json()) as {
      model?: string
      choices?: { message?: { content?: string } }[]
      usage?: { prompt_tokens?: number; completion_tokens?: number }
    }
    const content = json.choices?.[0]?.message?.content ?? ""
    if (!content) {
      return { ok: false, usage: { promptTokens: 0, completionTokens: 0, latencyMs: Date.now() - started }, error: "empty completion" }
    }
    return {
      ok: true,
      content,
      usage: {
        promptTokens: json.usage?.prompt_tokens ?? Math.ceil(opts.user.length / 4),
        completionTokens: json.usage?.completion_tokens ?? Math.ceil(content.length / 4),
        latencyMs: Date.now() - started,
      },
      model: json.model ?? opts.model,
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { ok: false, usage: { promptTokens: 0, completionTokens: 0, latencyMs: Date.now() - started }, error: message }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Built-in platform LLM bridge (z-ai-web-dev-sdk, glm-4-plus class).
 * Server-side only — dynamically imported so no client bundle can ever pull
 * the SDK in. Serves every JSON contract the Groq router serves, so the
 * engine keeps full LLM triage/patch synthesis even when Groq is unreachable
 * (e.g. locked-down networks) or no Groq key is configured.
 *
 * Rate-limit hygiene: calls are paced with a minimum interval, and transient
 * failures (429 / 5xx / timeouts) retry with exponential backoff before the
 * router is allowed to advance to the deterministic fallback.
 */
type ZaiInstance = Awaited<ReturnType<(typeof import("z-ai-web-dev-sdk"))["default"]["create"]>>
let zaiClient: Promise<ZaiInstance> | null = null

function getZai(): Promise<ZaiInstance> {
  if (!zaiClient) {
    zaiClient = (async () => {
      const { default: ZAI } = await import("z-ai-web-dev-sdk")
      return ZAI.create()
    })()
    zaiClient.catch(() => {
      zaiClient = null // reset so the next call re-initializes
    })
  }
  return zaiClient
}

const BRIDGE_MIN_INTERVAL_MS = 1500
let bridgeLastCall = 0

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// backoff schedule for transient failures — sized to ride out the provider's
// observed ~3-minute rate window far enough that a mid-run burst recovers
const BRIDGE_BACKOFF_MS = [1500, 3000, 6000, 12000, 24000]

async function platformBridgeChat(opts: ChatOptions): Promise<RawChatResult> {
  const started = Date.now()
  // pacing — keep a minimum gap between bridge calls so bursts of
  // per-finding patch drafts stay inside the provider's rate window
  const paceWait = bridgeLastCall + BRIDGE_MIN_INTERVAL_MS - Date.now()
  if (paceWait > 0) await sleep(paceWait)
  bridgeLastCall = Date.now()

  let lastError = "bridge unavailable"
  for (let attempt = 0; attempt <= BRIDGE_BACKOFF_MS.length; attempt++) {
    try {
      const zai = await getZai()
      const request = zai.chat.completions.create({
        messages: [
          // system role — the bridge previously shipped the operating instructions as
          // an assistant turn, degrading instruction-following for triage/patch calls
          { role: "system", content: opts.system },
          { role: "user", content: opts.user },
        ],
        thinking: { type: "disabled" },
      })
      const timeout = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("platform bridge timeout")), opts.timeoutMs ?? 60000)
      })
      const completion = (await Promise.race([request, timeout])) as {
        model?: string
        choices?: { message?: { content?: string } }[]
        usage?: { prompt_tokens?: number; completion_tokens?: number }
      }
      const content = completion.choices?.[0]?.message?.content ?? ""
      if (!content) {
        lastError = "empty completion"
      } else {
        return {
          ok: true,
          content,
          usage: {
            promptTokens: completion.usage?.prompt_tokens ?? Math.ceil(opts.user.length / 4),
            completionTokens: completion.usage?.completion_tokens ?? Math.ceil(content.length / 4),
            latencyMs: Date.now() - started,
          },
          model: completion.model ?? "glm-4-plus",
        }
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
    }
    const transient = /429|rate|too many|timeout|econn|fetch failed|socket|5\d\d/i.test(lastError)
    if (!transient || attempt === BRIDGE_BACKOFF_MS.length) break
    await sleep(BRIDGE_BACKOFF_MS[attempt] + Math.random() * 500)
  }
  return { ok: false, usage: { promptTokens: 0, completionTokens: 0, latencyMs: Date.now() - started }, error: lastError }
}

/** Extract the first JSON object from a model response (tolerates markdown fences and prose). */
export function extractJson(text: string): unknown | null {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/)
  const candidate = fenced ? fenced[1] : text
  const start = candidate.indexOf("{")
  const end = candidate.lastIndexOf("}")
  if (start === -1 || end === -1 || end <= start) return null
  try {
    return JSON.parse(candidate.slice(start, end + 1))
  } catch {
    return null
  }
}

/**
 * LLM router with output contract enforcement:
 * 1. Groq (when a key is configured), 2. the built-in platform bridge,
 * 3. deterministic fallback provider. Per provider: one retry on malformed
 * JSON, then the chain advances; transport/auth failure advances immediately.
 */
export async function llmRoute<T>(
  opts: ChatOptions,
  validate: (parsed: unknown) => T | null,
  fallback: () => { data: T; reasoning: string },
): Promise<LlmResult<T>> {
  const providers: { id: "GROQ" | "ZAI"; call: () => Promise<RawChatResult> }[] = []
  if (opts.apiKey) providers.push({ id: "GROQ", call: () => chatCompletion(opts) })
  providers.push({ id: "ZAI", call: () => platformBridgeChat(opts) })

  const degradedUsage: LlmUsage = { promptTokens: 0, completionTokens: 0, latencyMs: 0 }
  let lastError = "GROQ_UNAVAILABLE"

  for (const provider of providers) {
    for (let attempt = 1; attempt <= 2; attempt++) {
      const raw = await provider.call()
      if (raw.ok && raw.content) {
        const parsed = extractJson(raw.content)
        const data = parsed ? validate(parsed) : null
        if (data) {
          return {
            ok: true,
            data,
            usage: raw.usage,
            provider: provider.id,
            model: raw.model ?? opts.model,
            degraded: false,
          }
        }
        // malformed response — retry the same provider once (PRD: malformed = retry)
        degradedUsage.promptTokens += raw.usage.promptTokens
        degradedUsage.completionTokens += raw.usage.completionTokens
        lastError = `MALFORMED_${provider.id}`
        if (attempt === 1) continue
      } else {
        degradedUsage.promptTokens += raw.usage.promptTokens
        degradedUsage.completionTokens += raw.usage.completionTokens
        lastError = `${provider.id}_UNAVAILABLE`
      }
      break // advance to the next provider in the chain
    }
  }

  const fb = fallback()
  return {
    ok: false,
    data: fb.data,
    usage: degradedUsage,
    error: lastError,
    provider: "FALLBACK_HEURISTIC",
    model: "aegis-heuristic-v1",
    degraded: true,
  }
}

/** Connectivity probe used by the settings dialog — walks the same chain the engine runs. */
export async function probeGroq(apiKey: string, model: string): Promise<{ ok: boolean; message: string }> {
  let groqNote = ""
  if (apiKey) {
    try {
      const res = await fetch(GROQ_URL, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model,
          messages: [{ role: "user", content: "Reply with the JSON {\"ok\":true} and nothing else." }],
          max_tokens: 20,
          temperature: 0,
          response_format: { type: "json_object" },
        }),
      })
      if (res.ok) {
        const json = (await res.json()) as { choices?: { message?: { content?: string } }[] }
        return { ok: true, message: `Connected to Groq ${model} — ${JSON.stringify(json.choices?.[0]?.message?.content ?? "").slice(0, 80)}` }
      }
      groqNote = `Groq is unreachable from this network (HTTP ${res.status}). `
    } catch (err) {
      groqNote = `Groq is unreachable from this network (${err instanceof Error ? err.message : String(err)}). `
    }
  }
  // chain continues on the built-in platform bridge — the same path the engine takes
  const bridged = await platformBridgeChat({
    apiKey: "",
    model,
    system: "You are a JSON-only API. Respond with STRICT JSON, no prose.",
    user: 'Reply with the JSON {"ok":true} and nothing else.',
    maxTokens: 20,
  })
  if (bridged.ok && bridged.content && extractJson(bridged.content)) {
    return {
      ok: true,
      message: `${groqNote}LLM router engaged the built-in platform bridge (${bridged.model}) — full LLM triage and patch synthesis are active.`,
    }
  }
  return {
    ok: false,
    message: `${groqNote}Platform bridge also failed: ${bridged.error ?? "unknown error"}. Runs will degrade to the deterministic heuristic engine.`,
  }
}
