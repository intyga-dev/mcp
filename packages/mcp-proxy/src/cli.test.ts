// The proxy sits in the stdio path between an MCP client and a real MCP server, so its contract is
// only observable end to end: feed JSON-RPC in on stdin, watch what reaches the target versus what
// gets refused. These drive the real CLI as a subprocess with `cat` standing in for the target
// server — anything `cat` echoes back is something the proxy chose to forward.

import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { createServer } from "node:http"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { test } from "node:test"
import { fileURLToPath } from "node:url"

const CLI = fileURLToPath(new URL("./cli.ts", import.meta.url))
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-proxy-test-"))

function policyFile(rules: unknown): string {
  const file = path.join(tmp, `policy-${Math.random().toString(36).slice(2)}.json`)
  fs.writeFileSync(file, JSON.stringify({ rules }))
  return file
}

const rpc = (method: string, params?: unknown, id = 1) =>
  JSON.stringify({ jsonrpc: "2.0", id, method, params })

// The budget for `node --import tsx` to boot, compile the CLI and round-trip a line through `cat`.
// This used to be a flat 3s wait per test: long enough to be 39s of pure sleeping locally, and short
// enough that a loaded CI runner truncated stdout and the assertion read as "the proxy did not
// forward the call" — a spawn timeout wearing a logic bug's clothes.
//
// So it is a CAP now, not a duration. Output is collected until it goes quiet for QUIET_MS, which is
// the real signal that the proxy has said everything it is going to say. A fast machine finishes in
// well under a second per test; a slow one gets up to SETTLE_CAP_MS before being cut off.
const SETTLE_CAP_MS = Number(process.env.MCP_PROXY_SETTLE_MS ?? 15_000)
const QUIET_MS = 300

/**
 * Run the proxy with `cat` as the target, send `lines`, let it settle, then stop it and return
 * everything that reached stdout.
 *
 * We deliberately do NOT wait for the child to exit. A call that escalates to `require_approval`
 * blocks on the gateway, and with no gateway configured that request never completes — which is
 * itself correct fail-closed behaviour, but it means "the process ended" is not a signal we can wait
 * on. What matters for every case here is the same: after a fixed settle window, did the request
 * reach the target server or not?
 */
function runProxy(
  lines: string[],
  opts: {
    policy?: string
    enforcement?: string
    agentV1Module?: string
    gatewayUrl?: string
    quietMs?: number
  } = {},
) {
  return new Promise<string>((resolve, reject) => {
    const args = [CLI, "--target-command", "cat", "--enforcement", opts.enforcement ?? "local-first"]
    if (opts.policy) args.push("--local-policy", opts.policy)
    if (opts.agentV1Module) args.push("--agent-v1-module", opts.agentV1Module)
    if (opts.gatewayUrl) args.push("--gateway-url", opts.gatewayUrl)

    // `node --import tsx` rather than `npx tsx`: npx spawns tsx which spawns node, and killing the
    // top of that chain orphans the grandchild — which then holds this test's stdout pipe open and
    // stops the runner from ever exiting. One process is one process we can actually stop.
    const child = spawn(process.execPath, ["--import", "tsx", ...args], {
      stdio: ["pipe", "pipe", "inherit"],
    })
    let out = ""
    let lastData = Date.now()
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString()
      lastData = Date.now()
    })
    child.on("error", reject)

    for (const line of lines) child.stdin.write(`${line}\n`)

    const started = Date.now()
    const finish = () => {
      clearInterval(poll)
      child.kill("SIGKILL")
      child.stdout.destroy()
      child.stdin.destroy()
      resolve(out)
    }
    const poll = setInterval(() => {
      // Quiet only counts once something has arrived — otherwise a slow boot looks like silence and
      // every test would resolve empty in QUIET_MS.
      if (out.length > 0 && Date.now() - lastData >= (opts.quietMs ?? QUIET_MS)) return finish()
      if (Date.now() - started >= SETTLE_CAP_MS) return finish()
    }, 50)
  })
}

test("a local allow without v1 runtime still waits for the gateway", async () => {
  const line = rpc("tools/call", { name: "read_report", arguments: {} })
  const out = await runProxy([line], {
    policy: policyFile([{ action: "read_report", effect: "allow" }]),
  })
  assert.doesNotMatch(out, /"method":"tools\/call"/)
  assert.match(out, /Intyga Gateway Error/)
})

test("v1 agent mode does not forward a local allow without a verified receipt", async () => {
  const modulePath = path.join(tmp, "agent-v1-test.mjs")
  fs.writeFileSync(
    modulePath,
    `export default {
    requesterDid: "did:intyga:agent:test",
    approvers: { publicKeys: [] },
    verifier: {},
    prepare: async () => { throw new Error("trusted RP context unavailable") },
    liveConfig: async () => { throw new Error("trusted RP context unavailable") },
    readState: async () => { throw new Error("trusted RP state unavailable") },
    reserve: async () => false,
  }`,
  )
  const out = await runProxy([rpc("tools/call", { name: "read_report", arguments: {} })], {
    policy: policyFile([{ action: "read_report", effect: "allow" }]),
    agentV1Module: modulePath,
  })
  assert.doesNotMatch(out, /"method":"tools\/call"/)
  assert.match(out, /Intyga Gateway Error/)
})

test("a denied tool call is refused and never reaches the target", async () => {
  const line = rpc("tools/call", { name: "wipe_db", arguments: {} })
  const out = await runProxy([line], {
    policy: policyFile([{ action: "wipe_db", effect: "deny" }]),
  })
  assert.match(out, /Security Violation: Action 'wipe_db' is denied/)
  assert.match(out, /"code":-32603/)
  // The original request must not have been echoed by `cat`.
  assert.doesNotMatch(out, /"method":"tools\/call"/)
})

test("the refusal keeps the request's JSON-RPC id so the client can correlate it", async () => {
  const line = rpc("tools/call", { name: "wipe_db", arguments: {} }, 42)
  const out = await runProxy([line], {
    policy: policyFile([{ action: "wipe_db", effect: "deny" }]),
  })
  assert.match(out, /"id":42/)
})

test("non-tool traffic passes through untouched", async () => {
  const out = await runProxy([rpc("tools/list"), rpc("initialize")], {
    policy: policyFile([{ action: "anything", effect: "deny" }]),
  })
  assert.match(out, /"method":"tools\/list"/)
  assert.match(out, /"method":"initialize"/)
})

test("a line the proxy cannot parse is refused, never forwarded", async () => {
  // This test previously asserted the OPPOSITE — that unparseable framing was "not the proxy's to
  // swallow" and went to the target. The premise was that a line which is not JSON cannot be a
  // tools/call under any parser. That holds only for parsers as strict as V8's, and this proxy
  // exists to wrap third-party servers whose parser it does not control.
  const out = await runProxy(["this is not json"], {
    policy: policyFile([{ action: "x", effect: "deny" }]),
  })
  assert.doesNotMatch(out, /this is not json/, "unparseable input must not reach the target")
  assert.match(out, /-32700/, "and should get the JSON-RPC parse error instead")
})

test("a tools/call that only a lenient parser accepts cannot slip past the gate", async () => {
  // Measured: this exact line throws SyntaxError in Node's JSON.parse and parses cleanly in
  // Python's stdlib json.loads (NaN/Infinity are a documented CPython extension), yielding
  // method "tools/call" and tool "delete_prod_db". Under the old passthrough branch the policy
  // check, the approval and the audit entry were all skipped while a Python target executed the
  // tool. Trailing commas, comments and single quotes give the same shape against other targets.
  const lenient =
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_prod_db","arguments":{"x":NaN}}}'
  const out = await runProxy([lenient], {
    policy: policyFile([{ action: "delete_prod_db", effect: "allow" }]),
  })
  assert.doesNotMatch(out, /delete_prod_db/, "the ungated tool call must not reach the target")
  assert.match(out, /-32700/)
})

test("an action missing from the policy is not forwarded on its own authority", async () => {
  // Unknown action => require_approval. With no reachable gateway the call must fail closed:
  // whatever else happens, the request must not reach the target server.
  const line = rpc("tools/call", { name: "unlisted_action", arguments: {} })
  const out = await runProxy([line], {
    policy: policyFile([{ action: "something_else", effect: "allow" }]),
  })
  assert.doesNotMatch(out, /"method":"tools\/call"/)
})

test("protocol traffic is not stuck behind a pending approval", async () => {
  // The gated call blocks for up to two minutes waiting for a human. If `initialize`, `ping` and
  // `tools/list` queued behind it, the client would time them out and could tear down the session —
  // abandoning the approval it was waiting for. They must overtake it; none of them mutate anything.
  const gated = rpc("tools/call", { name: "unlisted_action", arguments: {} }, 1)
  const out = await runProxy([gated, rpc("initialize", undefined, 2), rpc("ping", undefined, 3)], {
    policy: policyFile([{ action: "something_else", effect: "allow" }]),
  })

  assert.match(out, /"method":"initialize"/, "initialize was blocked behind the pending approval")
  assert.match(out, /"method":"ping"/, "ping was blocked behind the pending approval")
  // The gated call itself is still waiting on a gateway that isn't there, so it must NOT be through.
  assert.doesNotMatch(out, /"method":"tools\/call"/)
})

test("approved tool calls reach the target in the order they were sent", async (t) => {
  // Bypassing the queue is only safe for non-tool traffic — tool calls must stay ordered relative to
  // each other, since two mutating actions arriving out of order is a correctness bug.
  //
  let nextNonce = 0
  const server = createServer((req, res) => {
    res.setHeader("content-type", "application/json")
    if (req.url === "/oauth/token") return void res.end(JSON.stringify({ access_token: "test-token" }))
    if (req.url === "/authorize/verify") return void res.end(JSON.stringify({ ok: true }))
    if (req.url === "/authorize") return void res.end(JSON.stringify({ nonce: `n-${++nextNonce}` }))
    return void res.end(JSON.stringify({ status: "APPROVED" }))
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  t.after(() => server.close())
  const address = server.address()
  assert.ok(address && typeof address !== "string")
  const out = await runProxy(
    [
      rpc("tools/call", { name: "read_report", arguments: { seq: 1 } }, 1),
      rpc("tools/call", { name: "read_report", arguments: { seq: 2 } }, 2),
      rpc("tools/call", { name: "read_report", arguments: { seq: 3 } }, 3),
    ],
    {
      policy: policyFile([{ action: "read_report", effect: "allow" }]),
      gatewayUrl: `http://127.0.0.1:${address.port}`,
      quietMs: 2_500, // the production approval poll is 2s per queued call
    },
  )
  const order = [...out.matchAll(/"seq":(\d)/g)].map((m) => m[1])
  assert.deepEqual(order, ["1", "2", "3"], `tool calls arrived out of order: ${out}`)
})

test("a policy file the gate cannot read never forwards the call", async () => {
  // `{"rules":{"a":1}}` is valid JSON in a shape evaluatePolicy did not expect. It used to throw on
  // `.find`, and processMessage's catch-all wrote the original line to the target — so one typo in
  // an operator's policy silently disabled the gate, with no error to the client and nothing logged.
  // A gate that opens when it breaks is worse than no gate.
  const file = path.join(tmp, `malformed-${Math.random().toString(36).slice(2)}.json`)
  fs.writeFileSync(file, JSON.stringify({ rules: { a: 1 } }))

  const line = rpc("tools/call", { name: "wire", arguments: { amount: 999_999 } })
  const out = await runProxy([line], { policy: file })

  assert.doesNotMatch(out, /"method":"tools\/call"/, "a malformed policy forwarded the call ungated")
})

test("a JSON-RPC batch carrying a tool call is refused, not passed through", async () => {
  // A batch is an array, so it has no top-level `.method` and used to classify as non-tool traffic —
  // going straight to the target with any number of ungated tool calls inside it. MCP removed
  // batching in revision 2025-06-18, and the proxy cannot know whether the target still honours it.
  const batch = JSON.stringify([
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "wire", arguments: { amount: 999_999 } } },
  ])
  // Even with the action explicitly allowed, the batch itself must not reach the target.
  const out = await runProxy([batch], { policy: policyFile([{ action: "wire", effect: "allow" }]) })

  assert.doesNotMatch(out, /"method":"tools\/call"/, "a batched tool call reached the target ungated")
  assert.match(out, /batches are not supported/)
  assert.match(out, /"code":-32600/)
})

test("a duplicate method key cannot make a tool call read as protocol traffic", async () => {
  // JS's JSON.parse keeps the LAST duplicate key; other parsers keep the first. This line reads as
  // `ping` here and as a tool call to a target server that disagrees. Forwarded messages are
  // re-serialized from what we parsed, so the target sees exactly one `method` — the one we gated on.
  const out = await runProxy(
    ['{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping","params":{"name":"wire"}}'],
    { policy: policyFile([{ action: "wire", effect: "deny" }]) },
  )
  assert.doesNotMatch(out, /"method":"tools\/call"/, "the target could still read this as a tool call")
})

test("gateway-enforced mode ignores a local allow rule", async () => {
  const line = rpc("tools/call", { name: "read_report", arguments: {} })
  const out = await runProxy([line], {
    enforcement: "gateway-enforced",
    policy: policyFile([{ action: "read_report", effect: "allow" }]),
  })
  // The local policy says allow, but only the gateway may decide in this mode — so nothing is
  // forwarded to the target without clearance.
  assert.doesNotMatch(out, /"method":"tools\/call"/)
})

/** A gateway that approves everything and records each `/authorize` body it was asked to approve. */
async function approvingGateway(t: { after: (fn: () => void) => void }) {
  const authorizeBodies: unknown[] = []
  const server = createServer((req, res) => {
    let body = ""
    req.on("data", (c: Buffer) => (body += c.toString()))
    req.on("end", () => {
      res.setHeader("content-type", "application/json")
      if (req.url === "/oauth/token") return void res.end(JSON.stringify({ access_token: "test-token" }))
      if (req.url === "/authorize/verify") return void res.end(JSON.stringify({ ok: true }))
      if (req.url === "/authorize") {
        authorizeBodies.push(JSON.parse(body))
        return void res.end(JSON.stringify({ nonce: `n-${authorizeBodies.length}` }))
      }
      return void res.end(JSON.stringify({ status: "APPROVED" }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  t.after(() => server.close())
  const address = server.address()
  assert.ok(address && typeof address !== "string")
  return { url: `http://127.0.0.1:${address.port}`, authorizeBodies }
}

test("non-object arguments are refused, never approved as {} and forwarded as sent", async (t) => {
  // Review repro (platform-mcp F2): `arguments: ["production"]` used to be approved as `{}` — the
  // human saw "drop_database with {}" — while the ORIGINAL message, array included, went to the
  // target on approval. Now the call is refused before any approval is raised.
  const gateway = await approvingGateway(t)
  const cases = [["production"], "production", 42, null, false]
  const out = await runProxy(
    cases.map((a, i) => rpc("tools/call", { name: "drop_database", arguments: a }, i + 1)),
    { policy: policyFile([{ action: "drop_database", effect: "allow" }]), gatewayUrl: gateway.url },
  )
  assert.doesNotMatch(out, /"method":"tools\/call"/, `a non-object arguments call reached the target: ${out}`)
  assert.equal([...out.matchAll(/"code":-32602/g)].length, cases.length, out)
  for (let id = 1; id <= cases.length; id++) assert.match(out, new RegExp(`"id":${id}\\b`))
  assert.deepEqual(
    gateway.authorizeBodies,
    [],
    "no approval may be raised for a call the gate cannot describe",
  )
})

test("a tools/call without a string name is refused", async (t) => {
  const gateway = await approvingGateway(t)
  const out = await runProxy(
    [rpc("tools/call", { name: ["drop_database"], arguments: {} }, 1), rpc("tools/call", undefined, 2)],
    { policy: policyFile([{ action: "", effect: "allow" }]), gatewayUrl: gateway.url },
  )
  assert.doesNotMatch(out, /"method":"tools\/call"/)
  assert.equal([...out.matchAll(/"code":-32602/g)].length, 2, out)
  assert.deepEqual(gateway.authorizeBodies, [])
})

test("an approved call is forwarded rebuilt from exactly the approved name and arguments", async (t) => {
  const gateway = await approvingGateway(t)
  const sent = {
    jsonrpc: "2.0",
    id: 7,
    method: "tools/call",
    smuggled: "top-level",
    params: {
      name: "transfer",
      arguments: { amount: 10, to: "acct-1", nested: { memo: "rent" } },
      _meta: { progressToken: "p-1", "vendor/override": { amount: 1_000_000 } },
      task: { ttl: 60_000 },
    },
  }
  const out = await runProxy([JSON.stringify(sent)], {
    policy: policyFile([{ action: "transfer", effect: "allow" }]),
    gatewayUrl: gateway.url,
    quietMs: 2_500, // the production approval poll is 2s
  })
  const forwarded = out
    .split("\n")
    .filter((l) => l.includes('"method":"tools/call"'))
    .map((l) => JSON.parse(l) as unknown)
  assert.equal(forwarded.length, 1, out)
  assert.deepEqual(forwarded[0], {
    jsonrpc: "2.0",
    id: 7,
    method: "tools/call",
    params: {
      name: "transfer",
      arguments: { amount: 10, to: "acct-1", nested: { memo: "rent" } },
      _meta: { progressToken: "p-1" },
    },
  })
  // And what reached the target is what the gateway was asked to approve.
  assert.equal(gateway.authorizeBodies.length, 1)
  const approved = gateway.authorizeBodies[0] as { params: unknown }
  assert.deepEqual(approved.params, sent.params.arguments)
})

test("omitted arguments execute as the approved empty object and invalid progress metadata is dropped", async (t) => {
  const gateway = await approvingGateway(t)
  const calls = [
    rpc("tools/call", { name: "refresh" }, 1),
    rpc("tools/call", { name: "refresh", _meta: { progressToken: { override: true } } }, 2),
    rpc("tools/call", { name: "refresh", arguments: {}, _meta: { progressToken: 0 } }, 3),
  ]
  const out = await runProxy(calls, { gatewayUrl: gateway.url, quietMs: 2_500 })
  const forwarded = out
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as unknown)
  assert.deepEqual(forwarded, [
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "refresh", arguments: {} } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "refresh", arguments: {} } },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "refresh", arguments: {}, _meta: { progressToken: 0 } },
    },
  ])
  assert.equal(gateway.authorizeBodies.length, 3)
  for (const approved of gateway.authorizeBodies) {
    assert.deepEqual((approved as { params: unknown }).params, {})
  }
})

test("a plain-http, non-loopback --gateway-url is refused at startup", async () => {
  // Unlike runProxy's children (SIGKILLed, so they never write coverage), this one exits normally.
  // Point NODE_V8_COVERAGE at a throwaway directory so its partial run is not merged into this
  // package's coverage gate. Deleting the variable is not enough: Node re-adds it to every child's
  // environment while coverage is on.
  const coverageSink = fs.mkdtempSync(path.join(tmp, "coverage-sink-"))
  const child = spawn(
    process.execPath,
    ["--import", "tsx", CLI, "--target-command", "cat", "--gateway-url", "http://gw.example"],
    { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NODE_V8_COVERAGE: coverageSink } },
  )
  let stderr = ""
  child.stderr.on("data", (d: Buffer) => {
    stderr += d.toString()
  })
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on("error", reject)
    child.on("close", resolve)
  })
  assert.equal(code, 1)
  assert.match(stderr, /--gateway-url \/ INTYGA_GATEWAY_URL must use https:\/\//)
})
