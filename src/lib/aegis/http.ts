// HTTP request-body guard — bounded JSON reads for every mutating API route.
// Security hardening (skill-audit run-3): route handlers previously trusted
// req.json() to buffer arbitrarily large bodies before zod ever ran. This guard
// enforces a byte ceiling at the stream level (Content-Length can lie, so the
// body itself is capped while reading), which bounds validator input regardless
// of any upstream parsing-library advisory (e.g. GHSA zod constrained-collection
// memory exhaustion). Failures map to 413 for size and 400 for shape.
const DEFAULT_MAX_BYTES = 256 * 1024

export type GuardedBody =
  | { ok: true; body: unknown }
  | { ok: false; error: string; status: number }

export async function readJsonBody(req: Request, maxBytes: number = DEFAULT_MAX_BYTES): Promise<GuardedBody> {
  const declared = Number(req.headers.get("content-length") ?? "0")
  if (Number.isFinite(declared) && declared > maxBytes) {
    return { ok: false, error: `payload too large (declared ${declared} bytes > ${maxBytes} limit)`, status: 413 }
  }
  const reader = req.body?.getReader()
  if (!reader) {
    // empty body: treat as an empty object so zod still validates the shape
    return { ok: true, body: {} }
  }
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    total += value.length
    if (total > maxBytes) {
      void reader.cancel().catch(() => {})
      return { ok: false, error: `payload too large (> ${maxBytes} bytes)`, status: 413 }
    }
    chunks.push(value)
  }
  let size = 0
  for (const c of chunks) size += c.length
  const merged = new Uint8Array(size)
  let offset = 0
  for (const c of chunks) {
    merged.set(c, offset)
    offset += c.length
  }
  try {
    return { ok: true, body: JSON.parse(new TextDecoder().decode(merged)) }
  } catch {
    return { ok: false, error: "invalid JSON body", status: 400 }
  }
}
