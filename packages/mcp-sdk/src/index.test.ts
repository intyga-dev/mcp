import assert from "node:assert/strict"
import crypto from "node:crypto"
import { test } from "node:test"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import {
  InMemoryTaskMessageQueue,
  InMemoryTaskStore,
} from "@modelcontextprotocol/sdk/experimental/tasks/stores/in-memory.js"
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"
import { intygafyServer } from "./index.ts"
import { canonicalIntentPayload } from "@intyga/sdk"

const TRUST = {
  tenantId: "11111111-1111-4111-8111-111111111111",
  requesterDid: "did:intyga:service:test",
  approvers: { dids: ["did:intyga:owner"], resolveKey: () => "unused" },
  requirement: { requiredApprovals: 1 },
}
const CONFIG = {
  gatewayUrl: "https://gw.example",
  clientId: "id",
  clientSecret: "secret",
  agentId: TRUST.requesterDid,
  executionTrust: TRUST,
  intervalMs: 1,
  enforcement: "local-first" as const,
}
type InternalTool = { handler: unknown; update(updates: Record<string, unknown>): void }
const tools = (server: McpServer) =>
  (server as unknown as { _registeredTools: Record<string, InternalTool> })._registeredTools
let dispatched = 0

function signedGateway(
  t: { after(fn: () => void): void },
  observe?: (event: "authorize" | "status" | "consume", body?: Record<string, unknown>) => void,
) {
  const original = globalThis.fetch
  t.after(() => {
    globalThis.fetch = original
  })
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  let action: Record<string, unknown>
  const nonce = "n-1"
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    if (u.endsWith("/oauth/token")) return Response.json({ access_token: "token" })
    if (u.endsWith("/dispatched")) {
      dispatched++
      return Response.json({ ok: true })
    }
    if (u.endsWith("/authorize/verify")) {
      observe?.("consume")
      return Response.json({ ok: true })
    }
    if (u.endsWith("/authorize")) {
      action = JSON.parse(String(init?.body))
      observe?.("authorize", action)
      return Response.json({ nonce })
    }
    observe?.("status")
    const expiresAt = new Date(Date.now() + 120_000).toISOString()
    const requirement = {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: true,
      signerClass: "human",
    }
    const canonicalPayload = canonicalIntentPayload({
      tenantId: TRUST.tenantId,
      target: action.target as string,
      actionType: action.actionType as string,
      display: action.actionDescription as string,
      params: action.params as Record<string, unknown>,
      requester: { did: TRUST.requesterDid, attestation: null },
      requirement,
      nonce,
      expiresAt,
    })
    return Response.json({
      status: "APPROVED",
      receipt: {
        canonicalPayload,
        actionDescription: action.actionDescription,
        params: action.params,
        requester: { did: TRUST.requesterDid, attestation: null },
        signerDid: "did:intyga:owner",
        signerPublicKey: publicKey,
        signature: crypto
          .sign("sha256", Buffer.from(canonicalPayload), { key: keys.privateKey, dsaEncoding: "ieee-p1363" })
          .toString("base64"),
        sigAlg: "ES256",
        verificationCode: "unused",
      },
    })
  }) as typeof fetch
  return {
    ...CONFIG,
    // Resolve only the approver: a resolver that hands the same key to every DID also maps it to the
    // excluded requester, and that key then counts for nobody (DIV §4.4.6).
    executionTrust: {
      ...TRUST,
      approvers: {
        dids: ["did:intyga:owner"],
        resolveKey: (did: string) => (did === "did:intyga:owner" ? publicKey : null),
      },
    },
  }
}

test("a real MCP client cannot execute a tool registered before wrapping", async (t) => {
  const server = new McpServer({ name: "test", version: "1" })
  let ran = false
  server.registerTool("wipe", { inputSchema: {} }, async () => {
    ran = true
    return { content: [{ type: "text" as const, text: "ran" }] }
  })
  intygafyServer(server, {
    ...CONFIG,
    localPolicyJson: JSON.stringify({ rules: [{ action: "wipe", effect: "deny" }] }),
  })
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "wipe", arguments: {} })
  assert.equal(ran, false)
  assert.match(JSON.stringify(result), /denied by Intyga policy/)
})

test("tool, registerTool, and registerToolTask all install gated handlers", () => {
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, CONFIG)
  const ordinary = async () => ({ content: [] })
  server.tool("old", ordinary)
  server.registerTool("current", { inputSchema: {} }, ordinary)
  const task = {
    createTask: async () => ({
      task: {
        taskId: "1",
        status: "working",
        createdAt: new Date().toISOString(),
        lastUpdatedAt: new Date().toISOString(),
        ttl: 60,
      },
    }),
    getTask: async () => {
      throw new Error("unused")
    },
    getTaskResult: async () => {
      throw new Error("unused")
    },
  }
  server.experimental.tasks.registerToolTask("task", { inputSchema: {} }, task as never)
  assert.notEqual(tools(server).old!.handler, ordinary)
  assert.notEqual(tools(server).current!.handler, ordinary)
  assert.notEqual(tools(server).task!.handler, task)
  assert.equal((tools(server).task!.handler as { getTask: unknown }).getTask, task.getTask)
})

test("a real MCP client task dispatch is approved before createTask runs", async (t) => {
  const taskStore = new InMemoryTaskStore()
  const server = new McpServer(
    { name: "test", version: "1" },
    {
      capabilities: { tasks: { requests: { tools: { call: {} } } } },
      taskStore,
      taskMessageQueue: new InMemoryTaskMessageQueue(),
    },
  )
  const events: string[] = []
  intygafyServer(
    server,
    signedGateway(t, (event) => {
      events.push(event)
    }),
  )
  let created = 0
  server.experimental.tasks.registerToolTask(
    "long",
    { inputSchema: {} },
    {
      createTask: async (_args, extra) => {
        assert.deepEqual(events, ["authorize", "status", "consume"])
        created++
        return { task: await extra.taskStore.createTask({ ttl: 60_000 }) }
      },
      getTask: async (_args, extra) => extra.taskStore.getTask(extra.taskId),
      getTaskResult: async (_args, extra) => extra.taskStore.getTaskResult(extra.taskId),
    },
  )
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
    taskStore.cleanup()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "long", arguments: {} }, CallToolResultSchema, {
    task: { ttl: 60_000 },
  })
  assert.equal(created, 1)
  assert.ok("task" in result)
})

test("a schema-less task approves empty params and preserves only task context", async (t) => {
  const taskStore = new InMemoryTaskStore()
  const server = new McpServer(
    { name: "test", version: "1" },
    {
      capabilities: { tasks: { requests: { tools: { call: {} } } } },
      taskStore,
      taskMessageQueue: new InMemoryTaskMessageQueue(),
    },
  )
  let approved: unknown
  intygafyServer(
    server,
    signedGateway(t, (event, body) => {
      if (event === "authorize") approved = body?.params
    }),
  )
  let created = 0
  server.experimental.tasks.registerToolTask("no-input-task", {}, {
    createTask: async (extra) => {
      created++
      return { task: await extra.taskStore.createTask({ ttl: 60_000 }) }
    },
    getTask: async (extra) => extra.taskStore.getTask(extra.taskId),
    getTaskResult: async (extra) => extra.taskStore.getTaskResult(extra.taskId),
  } as never)
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
    taskStore.cleanup()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "no-input-task" }, CallToolResultSchema, {
    task: { ttl: 60_000 },
  })
  assert.deepEqual(approved, {})
  assert.equal(created, 1)
  assert.ok("task" in result)
})

test("non-portable values produced by input parsing are refused before approval or execution", async (t) => {
  let requests = 0
  const originalFetch = globalThis.fetch
  t.after(() => {
    globalThis.fetch = originalFetch
  })
  globalThis.fetch = (async () => {
    requests++
    throw new Error("must not request approval")
  }) as typeof fetch
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, CONFIG)
  let executions = 0
  server.registerTool("non-json", { inputSchema: { value: z.string().transform(() => 1n) } }, async () => {
    executions++
    return { content: [] }
  })
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "non-json", arguments: { value: "x" } })
  assert.match(JSON.stringify(result), /arguments are not JSON/)
  assert.equal(requests, 0)
  assert.equal(executions, 0)
})

test("a terminal gateway refusal is returned to a real MCP client without executing", async (t) => {
  const originalFetch = globalThis.fetch
  t.after(() => {
    globalThis.fetch = originalFetch
  })
  globalThis.fetch = (async (url: unknown) => {
    const value = String(url)
    if (value.endsWith("/oauth/token")) return Response.json({ access_token: "token" })
    if (value.endsWith("/authorize")) return Response.json({ nonce: "refused-nonce" })
    return Response.json({ status: "DENIED", reason: "human denied the exact request" })
  }) as typeof fetch
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, CONFIG)
  let ran = false
  server.registerTool("refused", { inputSchema: {} }, async () => {
    ran = true
    return { content: [] }
  })
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "refused", arguments: {} })
  assert.equal(ran, false)
  assert.match(JSON.stringify(result), /status: DENIED/)
})

test("schema-less tools approve empty args without serializing MCP context", async (t) => {
  const originalFetch = globalThis.fetch
  t.after(() => {
    globalThis.fetch = originalFetch
  })
  let requested: Record<string, unknown> | undefined
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    if (String(url).endsWith("/oauth/token"))
      return { ok: true, status: 200, json: async () => ({ access_token: "token" }) } as Response
    if (String(url).endsWith("/authorize")) {
      requested = JSON.parse(String(init?.body)) as Record<string, unknown>
      throw new Error("stop")
    }
    throw new Error("unexpected")
  }) as typeof fetch
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, CONFIG)
  server.tool("noargs", async () => ({ content: [] }))
  const extra = { authInfo: { token: "bearer-sentinel" }, requestId: 7 }
  await (tools(server).noargs!.handler as (extra: unknown) => Promise<unknown>)(extra)
  assert.deepEqual(requested?.params, {})
  assert.equal(JSON.stringify(requested).includes("bearer-sentinel"), false)
})

test("approved schema-less tools receive their original MCP context, not context as args", async (t) => {
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, signedGateway(t))
  let seen: unknown
  server.tool("noargs", async (extra) => {
    seen = extra
    return { content: [] }
  })
  const extra = {
    requestId: 9,
    authInfo: { token: "transport-only" },
    _meta: { progressToken: "p-1", "vendor/override": { amount: 5000 } },
  }
  await (tools(server).noargs!.handler as (extra: unknown) => Promise<unknown>)(extra)
  assert.deepEqual(seen, {
    requestId: 9,
    authInfo: { token: "transport-only" },
    _meta: { progressToken: "p-1" },
  })
})

test("approved parsed arguments are snapshotted before waiting and the same snapshot executes", async (t) => {
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, signedGateway(t))
  let seen: unknown
  server.registerTool("transfer", { inputSchema: {} }, async (args) => {
    seen = args
    return { content: [] }
  })
  const mutable = { amount: 5 }
  const pending = (tools(server).transfer!.handler as (a: unknown, e: unknown) => Promise<unknown>)(
    mutable,
    {},
  )
  mutable.amount = 5000
  await pending
  assert.deepEqual(seen, { amount: 5 })
})

test("dispatch is reported after an approved handler attempt, including a throw", async (t) => {
  dispatched = 0
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, { ...signedGateway(t), reportDispatch: { evidenceWithinSeconds: 30 } })
  server.registerTool("throwing", { inputSchema: {} }, async () => {
    throw new Error("handler failed")
  })
  await assert.rejects(
    (tools(server).throwing!.handler as (a: unknown, e: unknown) => Promise<unknown>)({}, {}),
    /handler failed/,
  )
  assert.equal(dispatched, 1)
})

test("a real MCP client uses the current name after rename-only and callback updates", async (t) => {
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, {
    ...CONFIG,
    localPolicyJson: JSON.stringify({ rules: [{ action: "new", effect: "deny" }] }),
  })
  let ran = false
  const handle = server.registerTool("old", { inputSchema: {} }, async () => ({ content: [] }))
  handle.update({ name: "new" })
  handle.update({
    callback: async () => {
      ran = true
      return { content: [] }
    },
  })
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  const result = await client.callTool({ name: "new", arguments: {} })
  assert.equal(ran, false)
  assert.match(JSON.stringify(result), /denied by Intyga policy/)
})

test("schema-only update rewraps the retained callback with parsed arguments", async (t) => {
  const server = new McpServer({ name: "test", version: "1" })
  const events: string[] = []
  let approvedParams: unknown
  intygafyServer(
    server,
    signedGateway(t, (event, body) => {
      events.push(event)
      if (event === "authorize") approvedParams = body?.params
    }),
  )
  let seen: unknown
  const handle = server.tool("dynamic", async (extra) => {
    assert.deepEqual(events, ["authorize", "status", "consume"])
    seen = extra
    return { content: [] }
  })
  handle.update({ paramsSchema: { amount: z.number() } })
  const client = new Client({ name: "client", version: "1" })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  t.after(async () => {
    await client.close()
    await server.close()
  })
  await server.connect(serverTransport)
  await client.connect(clientTransport)
  await client.callTool({ name: "dynamic", arguments: { amount: 7 } })
  assert.deepEqual(approvedParams, { amount: 7 })
  assert.deepEqual(seen, { amount: 7 })
})

test("unsupported MCP internals and missing trust fail during setup", () => {
  assert.throws(() => intygafyServer({} as McpServer, CONFIG), /supports exactly 1\.32\.1/)
  assert.throws(
    () =>
      intygafyServer(new McpServer({ name: "test", version: "1" }), { ...CONFIG, executionTrust: undefined }),
    /exactly one/,
  )
  for (const executionTrust of [
    null,
    { ...TRUST, tenantId: "" },
    { ...TRUST, tenantId: 42 },
    { ...TRUST, requesterDid: "" },
    { ...TRUST, requesterDid: 42 },
    { ...TRUST, requirement: undefined },
    { ...TRUST, requirement: { requiredApprovals: 0 } },
    { ...TRUST, requirement: { requiredApprovals: 65 } },
    { ...TRUST, requirement: { requiredApprovals: 1.5 } },
    { ...TRUST, requirement: { requiredApprovals: 1, requireHardwareKey: "yes" } },
    { ...TRUST, requirement: { requiredApprovals: 1, requesterCannotApprove: "yes" } },
    { ...TRUST, requirement: { requiredApprovals: 1, allowedAaguids: [] } },
    { ...TRUST, requirement: { requiredApprovals: 1, signerClass: "human" } },
    { ...TRUST, requirement: { requiredApprovals: 1, futurePolicy: true } },
    { ...TRUST, approvers: { dids: ["did:intyga:stable-owner"] } },
    { ...TRUST, approvers: { dids: ["did:intyga:key:not-a-canonical-key"] } },
    { ...TRUST, approvers: undefined },
    { ...TRUST, approvers: {} },
    { ...TRUST, approvers: { publicKeys: [] } },
    { ...TRUST, approvers: { publicKeys: [""] } },
    { ...TRUST, approvers: { dids: [] } },
    { ...TRUST, approvers: { dids: [42] } },
    { ...TRUST, approvers: { dids: ["did:intyga:owner"], resolveKey: "not-a-function" } },
    { ...TRUST, approvers: { publicKeys: ["key"], resolveKey: () => "key" } },
    { ...TRUST, approvers: { publicKeys: ["key"], dids: [] } },
    { ...TRUST, approvers: { publicKeys: [], dids: ["did:intyga:owner"], resolveKey: () => "key" } },
    { ...TRUST, approvers: { dids: ["did:intyga:owner"], publicKeys: ["key"], resolveKey: () => "key" } },
  ]) {
    assert.throws(
      () =>
        intygafyServer(new McpServer({ name: "test", version: "1" }), {
          ...CONFIG,
          executionTrust: executionTrust as never,
        }),
      /object|tenantId|requesterDid|requirement|unsupported|approvers|resolveKey|never both|trust anchor/,
    )
  }
  assert.doesNotThrow(() =>
    intygafyServer(new McpServer({ name: "test", version: "1" }), {
      ...CONFIG,
      executionTrust: {
        ...TRUST,
        approvers: { dids: [`did:intyga:key:${"A".repeat(43)}`] },
      },
    }),
  )
  assert.doesNotThrow(() =>
    intygafyServer(new McpServer({ name: "test", version: "1" }), {
      ...CONFIG,
      executionTrust: {
        ...TRUST,
        requirement: {
          requiredApprovals: 1,
          requireHardwareKey: true,
          requesterCannotApprove: true,
        },
        approvers: { publicKeys: ["trusted-key"] },
      },
    }),
  )
})

test("unsupported pre-registered handlers fail setup before the server can become callable", () => {
  for (const handler of [42, {}, { createTask: "not-a-function" }]) {
    const server = new McpServer({ name: "test", version: "1" })
    server.registerTool("unsafe", { inputSchema: {} }, (async () => ({ content: [] })) as never)
    tools(server).unsafe!.handler = handler
    assert.throws(() => intygafyServer(server, CONFIG), /Unsupported handler/)
  }
})

test("updating with an already gated callback neither unwraps nor double-wraps it", async () => {
  const server = new McpServer({ name: "test", version: "1" })
  intygafyServer(server, CONFIG)
  const handle = server.registerTool("stable", { inputSchema: {} }, async () => ({ content: [] }))
  const gated = tools(server).stable!.handler
  handle.update({ callback: gated as never })
  assert.equal(tools(server).stable!.handler, gated)
  handle.update({ description: "still stable" })
  assert.equal(tools(server).stable!.handler, gated)
})

test("incomplete AI runtimes fail during setup before any handler or request can run", () => {
  let requests = 0
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async () => {
    requests++
    throw new Error("unexpected")
  }) as typeof fetch
  try {
    for (const missing of ["prepare", "liveConfig", "readState", "reserve"] as const) {
      const runtime = {
        ...TRUST,
        verifier: {},
        prepare: async () => ({ action: { reversibility: "reversible", amount: null } }),
        liveConfig: async () => ({ model: {}, tools: [], systemPrompt: "" }),
        readState: async () => ({ head: null, seq: "0", aggregate: null }),
        reserve: async () => true,
      }
      delete (runtime as unknown as Record<string, unknown>)[missing]
      assert.throws(
        () =>
          intygafyServer(new McpServer({ name: "test", version: "1" }), {
            ...CONFIG,
            executionTrust: undefined,
            agentV1: runtime as never,
          }),
        /must provide/,
      )
    }
    for (const verifier of [undefined, null, "not-an-object"]) {
      assert.throws(
        () =>
          intygafyServer(new McpServer({ name: "test", version: "1" }), {
            ...CONFIG,
            executionTrust: undefined,
            agentV1: {
              ...TRUST,
              verifier,
              prepare: async () => ({ action: { reversibility: "reversible", amount: null } }),
              liveConfig: async () => ({ model: {}, tools: [], systemPrompt: "" }),
              readState: async () => ({ head: null, seq: "0", aggregate: null }),
              reserve: async () => true,
            } as never,
          }),
        /verifier must be an object/,
      )
    }
    assert.equal(requests, 0)
  } finally {
    globalThis.fetch = originalFetch
  }
})
