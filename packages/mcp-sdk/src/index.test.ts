// intygafyServer() monkey-patches server.tool so every registered handler goes through the approval
// gate. These tests cover the wrapping contract (does the original still get registered correctly?)
// and the enforcement contract (can a call reach the real handler without clearance?).

import assert from "node:assert/strict"
import { test } from "node:test"
import { intygafyServer } from "./index.ts"

type ToolFn = (...args: unknown[]) => unknown

/**
 * A stand-in McpServer that records what it was asked to register.
 *
 * It exposes BOTH entrypoints on purpose. The real @modelcontextprotocol/sdk marks `tool()`
 * `@deprecated` and routes `registerTool()` through a separate path that never calls it, so a double
 * offering only `tool` cannot see whether the wrapper covers the entrypoint consumers actually use.
 * The returned handle carries `update()` for the same reason — it replaces the handler after
 * registration.
 */
function fakeServer() {
  const registered: unknown[][] = []
  const handle = {
    update: (updates: Record<string, unknown>) => {
      registered.push(["update", updates])
      return undefined
    },
  }
  const record = (...args: unknown[]) => {
    registered.push(args)
    return handle
  }
  const server = {
    tool: record as ToolFn,
    registerTool: record as ToolFn,
  }
  return { server, registered, handle }
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
  intygafyServer(server as never, { ...CONFIG, ...config } as never)
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
  const { server, registered, handle } = fakeServer()
  intygafyServer(server as never, CONFIG as never)
  const result = server.tool("transfer", { schema: true })
  // The server's own return value reaches the caller — the wrapper patches the handle in place
  // rather than substituting one, so `update()` on it is gated without changing its identity.
  assert.equal(result, handle)
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
  assert.match(result.content[0]!.text, /denied by Intyga policy/)
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
    assert.match(result.content[0]!.text, /Intyga Gateway Error: connection refused/)
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
    if (u.endsWith("/authorize")) return reply({ nonce: "n-1", status: "PENDING" })
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
    if (u.endsWith("/authorize")) return reply({ nonce: "n-1", status: "PENDING" })
    if (u.endsWith("/authorize/verify")) return reply({ ok: true })
    if (u.includes("/authorize/")) return reply({ status: "APPROVED" })
    return reply({ ok: true })
  }) as typeof fetch
  try {
    const { secured } = wrapHandler({}, async () => "executed")
    assert.equal(await secured({ amount: 5000, to: "Acme" }, {}), "executed")

    // The consume call must carry the same params the handler is about to act on — that binding is
    // what makes the human's approval mean anything.
    const consume = calls.find((c) => c.url.endsWith("/authorize/verify"))
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
    if (u.endsWith("/authorize")) return reply({ nonce: "n-1", status: "PENDING" })
    // The human approved, but the redemption is refused — a replay / double-spend guard firing.
    if (u.endsWith("/authorize/verify")) return reply({ error: "already consumed" }, false)
    if (u.includes("/authorize/")) return reply({ status: "APPROVED" })
    throw new Error(`unexpected route: ${u}`)
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

// ─── Every registration entrypoint must be gated ─────────────────────────────
//
// The wrapper used to patch only `server.tool`. In @modelcontextprotocol/sdk every `tool()` overload
// is marked `@deprecated Use registerTool instead`, and `registerTool` calls `_createRegisteredTool`
// directly — it never routes through `this.tool`. So a consumer following current MCP docs got a
// server with no gate on any tool, no warning, and a wrapper that returned normally.

test("registerTool is gated, not just the deprecated tool()", async () => {
  const { server, registered } = fakeServer()
  intygafyServer(server as never, CONFIG as never)

  let ran = false
  server.registerTool("wipe_db", { description: "d" }, async () => {
    ran = true
    return "ran"
  })

  const args = registered[0]!
  const secured = args[args.length - 1] as ToolFn
  // No policy allows this, and no gateway is reachable, so it must not reach the original handler.
  const out = (await secured({}, {})) as { content: { text: string }[] }
  assert.equal(ran, false, "registerTool handler ran without passing the gate")
  assert.match(out.content[0]!.text, /Intyga/)
})

test("replacing the handler via update() re-gates it", async () => {
  const { server, registered, handle } = fakeServer()
  intygafyServer(server as never, CONFIG as never)

  const returned = server.registerTool("wipe_db", { description: "d" }, async () => "original")
  // The wrapper patches the handle in place, so what the caller holds is what it must gate through.
  assert.equal(returned, handle)

  let ran = false
  returned.update({
    callback: async () => {
      ran = true
      return "replacement"
    },
  })

  const updateCall = registered.find((r) => r[0] === "update")!
  const replaced = (updateCall[1] as { callback: ToolFn }).callback
  const out = (await replaced({}, {})) as { content: { text: string }[] }
  assert.equal(ran, false, "a handler swapped in via update() ran ungated")
  assert.match(out.content[0]!.text, /Intyga/)
})

// ─── Wrapping edge cases ─────────────────────────────────────────────────────
// The wrapper patches whatever the host server hands back, so it has to cope with hosts that differ
// from the current @modelcontextprotocol/sdk without either throwing or quietly dropping the gate.

test("a server with no registerTool is still wrapped on tool(), without throwing", async () => {
  // registerTool arrived in a later SDK than tool(). Binding it unconditionally threw on any server
  // (or test double) that predates it, which would take down every consumer on an older SDK.
  const registered: unknown[][] = []
  const server = {
    tool: ((...args: unknown[]) => {
      registered.push(args)
      return "registered"
    }) as ToolFn,
  }
  intygafyServer(server as never, CONFIG as never)
  assert.equal("registerTool" in server, false, "registerTool was invented on a server that lacks it")

  let ran = false
  server.tool("wipe_db", async () => {
    ran = true
    return "ran"
  })
  const args = registered[0]!
  const secured = args[args.length - 1] as ToolFn
  await secured({}, {})
  assert.equal(ran, false, "the deprecated path lost its gate when registerTool was absent")
})

test("a registration handle without update() is returned untouched", () => {
  // Nothing to patch, and nothing to blow up on: a host that returns a plain value from tool() must
  // still get a working gate on the handler itself.
  for (const returnValue of ["registered", null, undefined, 42]) {
    const server = { tool: ((..._a: unknown[]) => returnValue) as ToolFn }
    intygafyServer(server as never, CONFIG as never)
    assert.equal(
      server.tool("wipe_db", async () => "ran"),
      returnValue,
    )
  }
})

test("update() without a callback is forwarded untouched", () => {
  const { server, registered } = fakeServer()
  intygafyServer(server as never, CONFIG as never)
  const handle = server.registerTool("wipe_db", { description: "d" }, async () => "ran") as {
    update: (u: Record<string, unknown>) => void
  }

  // Renaming or re-describing a tool does not replace its handler, so there is nothing to re-gate —
  // and the wrapper must not inject a callback that was never asked for.
  handle.update({ description: "new description" })
  const updateCall = registered.find((r) => r[0] === "update")!
  assert.deepEqual(updateCall[1], { description: "new description" })
})

test("update() that renames AND replaces the handler gates against the new name", async () => {
  // The gate evaluates policy on the tool's name, so a rename in the same call has to be the name
  // the replacement handler is judged by — otherwise the policy for the old name silently applies.
  const { server, registered } = fakeServer()
  intygafyServer(
    server as never,
    {
      ...CONFIG,
      enforcement: "local-first",
      // Permissive for the OLD name only. If the wrapper gated against it, the handler would run.
      localPolicyJson: JSON.stringify({ rules: [{ action: "old_name", effect: "allow" }] }),
    } as never,
  )

  const handle = server.registerTool("old_name", { description: "d" }, async () => "original") as {
    update: (u: Record<string, unknown>) => void
  }

  let ran = false
  handle.update({
    name: "new_name",
    callback: async () => {
      ran = true
      return "replacement"
    },
  })

  const updateCall = registered.find((r) => r[0] === "update")!
  const replaced = (updateCall[1] as { callback: ToolFn }).callback
  const out = (await replaced({}, {})) as { content: { text: string }[] }
  assert.equal(ran, false, "the renamed tool was judged by the old name's policy")
  assert.match(out.content[0]!.text, /Intyga/)
})

test("a registration whose first argument is not a name still gates, under an empty name", () => {
  // Defensive: an unfamiliar overload must not make the wrapper skip gating. An empty name matches no
  // policy rule, so evaluatePolicy escalates — the fail-closed direction.
  const { server, registered } = fakeServer()
  intygafyServer(server as never, CONFIG as never)
  server.tool({ notAName: true }, async () => "ran")
  const args = registered[0]!
  assert.notEqual(args[args.length - 1], undefined)
  assert.equal(typeof args[args.length - 1], "function")
})
