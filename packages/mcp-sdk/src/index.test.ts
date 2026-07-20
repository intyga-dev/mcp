// sakrafyServer() monkey-patches server.tool so every registered handler goes through the approval
// gate. These tests cover the wrapping contract (does the original still get registered correctly?)
// and the enforcement contract (can a call reach the real handler without clearance?).

import assert from "node:assert/strict"
import { test } from "node:test"
import { sakrafyServer } from "./index.ts"

type ToolFn = (...args: unknown[]) => unknown

/** A stand-in McpServer that just records what `tool()` was called with. */
function fakeServer() {
  const registered: unknown[][] = []
  const server = {
    tool: ((...args: unknown[]) => {
      registered.push(args)
      return "registered"
    }) as ToolFn,
  }
  return { server, registered }
}

const CONFIG = {
  gatewayUrl: "http://gw.example",
  clientId: "id",
  clientSecret: "secret",
  agentId: "agent-1",
}

/** Register a tool through the wrapper and hand back the handler the server actually received. */
function wrapHandler(
  config: Partial<typeof CONFIG> & Record<string, unknown>,
  handler: ToolFn,
  extraArgs: unknown[] = [],
) {
  const { server, registered } = fakeServer()
  sakrafyServer(server as never, { ...CONFIG, ...config } as never)
  server.tool("transfer", ...extraArgs, handler)
  const args = registered[0]!
  return { args, secured: args[args.length - 1] as ToolFn }
}

test("the wrapped tool is still registered with its name and intermediate args intact", () => {
  const schema = { amount: "number" }
  const { args } = wrapHandler({}, async () => "ran", ["description", schema])
  assert.equal(args[0], "transfer")
  assert.equal(args[1], "description")
  assert.equal(args[2], schema)
  assert.equal(args.length, 4)
})

test("the registered handler is the wrapper, not the original", () => {
  const original = async () => "ran"
  const { secured } = wrapHandler({}, original)
  assert.notEqual(secured, original)
  assert.equal(typeof secured, "function")
})

test("a registration with no handler is passed straight through untouched", () => {
  const { server, registered } = fakeServer()
  sakrafyServer(server as never, CONFIG as never)
  const result = server.tool("transfer", { schema: true })
  assert.equal(result, "registered")
  assert.deepEqual(registered[0], ["transfer", { schema: true }])
})

test("an allowed action reaches the original handler with its arguments", async () => {
  let seen: unknown
  const { secured } = wrapHandler(
    {
      enforcement: "local-first",
      localPolicyJson: JSON.stringify({ rules: [{ action: "transfer", effect: "allow" }] }),
    },
    async (a: unknown) => {
      seen = a
      return "executed"
    },
  )
  assert.equal(await secured({ amount: 5 }, {}), "executed")
  assert.deepEqual(seen, { amount: 5 })
})

test("the handler's extra context argument is forwarded", async () => {
  let seenExtra: unknown
  const { secured } = wrapHandler(
    {
      enforcement: "local-first",
      localPolicyJson: JSON.stringify({ rules: [{ action: "transfer", effect: "allow" }] }),
    },
    async (_a: unknown, extra: unknown) => {
      seenExtra = extra
      return "executed"
    },
  )
  const extra = { signal: "abort-ish" }
  await secured({}, extra)
  assert.equal(seenExtra, extra)
})

test("a denied action never reaches the original handler", async () => {
  let ran = false
  const { secured } = wrapHandler(
    {
      enforcement: "local-first",
      localPolicyJson: JSON.stringify({ rules: [{ action: "transfer", effect: "deny" }] }),
    },
    async () => {
      ran = true
      return "executed"
    },
  )
  const result = (await secured({}, {})) as { content: { text: string }[] }
  assert.equal(ran, false, "denied action executed anyway")
  assert.match(result.content[0]!.text, /denied by SÄKRA policy/)
})

test("a gateway that cannot be reached fails closed, without executing", async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async () => {
    throw new Error("connection refused")
  }) as typeof fetch
  try {
    let ran = false
    const { secured } = wrapHandler({}, async () => {
      ran = true
      return "executed"
    })
    // No policy => require_approval => the gateway is consulted, and it is unreachable. The action
    // must be reported as failed, never optimistically executed.
    const result = (await secured({}, {})) as { content: { text: string }[] }
    assert.equal(ran, false, "handler ran despite the gateway being unreachable")
    assert.match(result.content[0]!.text, /SÄKRA Gateway Error: connection refused/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test("a rejected approval is reported and the handler never runs", async () => {
  const originalFetch = globalThis.fetch
  const reply = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as unknown as Response
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    if (u.endsWith("/oauth/token")) return reply({ access_token: "tok" })
    if (u.endsWith("/action/request")) return reply({ nonce: "n-1" })
    return reply({ status: "DENIED" })
  }) as typeof fetch
  try {
    let ran = false
    const { secured } = wrapHandler({}, async () => {
      ran = true
      return "executed"
    })
    const result = (await secured({}, {})) as { content: { text: string }[] }
    assert.equal(ran, false, "handler ran despite the human denying it")
    assert.match(result.content[0]!.text, /rejected or timed out \(status: DENIED\)/)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test("an approved action is consumed before the handler runs, binding the exact params", async () => {
  const originalFetch = globalThis.fetch
  const calls: { url: string; body: unknown }[] = []
  const reply = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as unknown as Response
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    // The token call is form-encoded, everything else is JSON — don't assume.
    let body: unknown
    try {
      body = init?.body ? JSON.parse(String(init.body)) : undefined
    } catch {
      body = String(init?.body)
    }
    calls.push({ url: u, body })
    if (u.endsWith("/oauth/token")) return reply({ access_token: "tok" })
    if (u.endsWith("/action/request")) return reply({ nonce: "n-1" })
    if (u.includes("/action/status/")) return reply({ status: "APPROVED" })
    return reply({ ok: true })
  }) as typeof fetch
  try {
    const { secured } = wrapHandler({}, async () => "executed")
    assert.equal(await secured({ amount: 5000, to: "Acme" }, {}), "executed")

    // The consume call must carry the same params the handler is about to act on — that binding is
    // what makes the human's approval mean anything.
    const consume = calls.find((c) => c.url.endsWith("/action/consume"))
    assert.ok(consume, "approved action was executed without being consumed")
    assert.deepEqual((consume.body as { params: unknown }).params, { amount: 5000, to: "Acme" })
    assert.equal((consume.body as { nonce: string }).nonce, "n-1")
  } finally {
    globalThis.fetch = originalFetch
  }
})

test("a failed consume blocks execution even though the human approved", async () => {
  const originalFetch = globalThis.fetch
  const reply = (body: unknown, ok = true) =>
    ({ ok, status: ok ? 200 : 409, json: async () => body }) as unknown as Response
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    if (u.endsWith("/oauth/token")) return reply({ access_token: "tok" })
    if (u.endsWith("/action/request")) return reply({ nonce: "n-1" })
    if (u.includes("/action/status/")) return reply({ status: "APPROVED" })
    return reply({ error: "already consumed" }, false) // replay / double-spend guard
  }) as typeof fetch
  try {
    let ran = false
    const { secured } = wrapHandler({}, async () => {
      ran = true
      return "executed"
    })
    const result = (await secured({}, {})) as { content: { text: string }[] }
    assert.equal(ran, false, "handler ran despite consume failing")
    assert.match(result.content[0]!.text, /Failed to consume/)
  } finally {
    globalThis.fetch = originalFetch
  }
})
