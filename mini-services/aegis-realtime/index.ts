// AEGIS realtime service — socket.io broadcaster on port 3001.
// The Next.js engine POSTs events here after persisting them to the event store;
// subscribed consoles receive them live. Dumb pipe only: all truth lives in the store.
//
// Security hardening (audit run-2):
//   1. The /broadcast bridge is authenticated with the AEGIS_BRIDGE_TOKEN shared
//      secret (timing-safe compare) — unauthenticated peers can no longer forge
//      events, including through the gateway (?XTransformPort=3001).
//   2. Bridge request bodies are size-capped (512 KB) — no unbounded buffering.
//   3. Socket handshakes are origin-gated: a browser Origin may only connect when
//      its host matches the request Host header (the console's own origin through
//      the gateway). Non-browser clients (no Origin) are allowed.
import { createServer } from 'http'
import { createHash, timingSafeEqual } from 'crypto'
import { readFileSync } from 'fs'
import { Server } from 'socket.io'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

// ---------------------------------------------------------------------------
// Environment: this service runs with its own CWD (mini-services/aegis-realtime),
// so Bun's automatic .env load would miss the project root .env — load it
// explicitly. Real environment variables always win over file values.
// ---------------------------------------------------------------------------
function loadRootEnv(): void {
  if (process.env.AEGIS_BRIDGE_TOKEN) return
  try {
    const here = dirname(fileURLToPath(import.meta.url))
    const envPath = join(here, '..', '..', '.env')
    const text = readFileSync(envPath, 'utf8') as string
    for (const line of text.split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/)
      if (!m) continue
      const key = m[1]
      const raw = m[2]
      const value = (raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))
        ? raw.slice(1, -1)
        : raw
      if (!(key in process.env)) process.env[key] = value
    }
  } catch {
    /* no root .env — token must come from the real environment */
  }
}
loadRootEnv()

const BRIDGE_TOKEN = process.env.AEGIS_BRIDGE_TOKEN ?? ''
const BRIDGE_BODY_LIMIT = 512 * 1024 // 512 KB

/** Constant-time secret comparison (hash both sides so length never short-circuits). */
function tokenMatches(provided: string): boolean {
  if (!BRIDGE_TOKEN || !provided) return false
  const a = createHash('sha256').update(provided).digest()
  const b = createHash('sha256').update(BRIDGE_TOKEN).digest()
  return timingSafeEqual(a, b)
}

/** True when a browser Origin's host matches the request Host (same-site console). */
function originMatchesHost(req: import('http').IncomingMessage): boolean {
  const origin = req.headers.origin
  if (!origin || typeof origin !== 'string') return true // non-browser / same-origin GET
  const host = String(req.headers.host ?? '')
  try {
    const originHost = new URL(origin).host
    const stripPort = (h: string) => h.split(':')[0].toLowerCase()
    return stripPort(originHost) === stripPort(host) && stripPort(host) !== ''
  } catch {
    return false
  }
}

const httpServer = createServer((req, res) => {
  // internal bridge from the AEGIS engine (server-to-server). Reachable in this
  // sandbox via the gateway query param, hence the shared-secret requirement.
  if (req.method === 'POST' && req.url?.split('?')[0] === '/broadcast') {
    if (!tokenMatches(String(req.headers['x-bridge-token'] ?? ''))) {
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end('{"ok":false,"error":"bridge token missing or invalid"}')
      return
    }
    let body = ''
    let oversized = false
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString()
      if (body.length > BRIDGE_BODY_LIMIT) {
        oversized = true
        req.destroy() // refuse to buffer unbounded payloads
      }
    })
    req.on('end', () => {
      if (oversized) return // connection already torn down
      try {
        const payload = JSON.parse(body) as { runId: string; event: Record<string, unknown> }
        if (!payload.runId || !payload.event) throw new Error('bad payload')
        const rooms: string[] = []
        for (const room of io.sockets.adapter.rooms.keys()) rooms.push(room)
        const runRooms = rooms.filter((r: string) => r.startsWith('run:'))
        console.log(`[aegis-realtime] broadcast runId=${payload.runId} rooms=[${runRooms.join(', ')}] clients=${io.engine.clientsCount}`)
        io.to(`run:${payload.runId}`).emit('aegis:event', payload.event)
        io.emit('aegis:activity', {
          runId: payload.runId,
          type: payload.event.type,
          level: payload.event.level,
          message: payload.event.message,
          ts: payload.event.ts,
        })
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end('{"ok":true}')
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end('{"ok":false}')
      }
    })
    return
  }
  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end('{"ok":false}')
})

// Engine.io keeps its default path (/socket.io) so the internal /broadcast HTTP bridge
// stays available on the same server. Caddy routes by the XTransformPort query parameter.
//
// Origin gate: allowRequest rejects cross-site browser handshakes before the
// connection is upgraded; cors reflects the (already vetted) origin for the
// polling transport.
const io = new Server(httpServer, {
  cors: { origin: true, methods: ['GET', 'POST'] },
  allowRequest: (req, cb) => cb(null, originMatchesHost(req)),
  pingTimeout: 60000,
  pingInterval: 25000,
})

io.on('connection', (socket) => {
  console.log(`[aegis-realtime] client connected: ${socket.id}`)
  socket.on('subscribe', (runId: string) => {
    console.log(`[aegis-realtime] subscribe ${socket.id} -> run:${runId}`)
    if (typeof runId === 'string' && runId.length > 0 && runId.length < 64) {
      socket.join(`run:${runId}`)
    }
  })
  socket.on('unsubscribe', (runId: string) => {
    socket.leave(`run:${runId}`)
  })
  socket.on('ping-console', (cb: (v: unknown) => void) => {
    if (typeof cb === 'function') cb({ ok: true, ts: Date.now() })
  })
})

const PORT = 3001
httpServer.listen(PORT, () => {
  console.log(`[aegis-realtime] listening on ${PORT} (bridge token ${BRIDGE_TOKEN ? 'configured' : 'MISSING — /broadcast is closed'})`)
})
