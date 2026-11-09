// The proxy sits in the stdio path between an MCP client and a real MCP server, so its contract is
// only observable end to end: feed JSON-RPC in on stdin, watch what reaches the target versus what
// gets refused. These drive the real CLI as a subprocess with `cat` standing in for the target
// server — anything `cat` echoes back is something the proxy chose to forward.

import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import crypto from "node:crypto"
import { createServer } from "node:http"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { after, test } from "node:test"
import { fileURLToPath } from "node:url"
import { canonicalIntentPayload } from "@intyga/mcp-schemas"

const CLI = process.env.MCP_PROXY_TEST_CLI ?? fileURLToPath(new URL("./cli.ts", import.meta.url))
const cliNodeArgs = (args: string[]) => [...(CLI.endsWith(".ts") ? ["--import", "tsx"] : []), CLI, ...args]
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-proxy-test-"))
// Every run used to leave this directory behind in os.tmpdir().
after(() => fs.rmSync(tmp, { recursive: true, force: true }))
const serviceTrustModule = path.join(tmp, "execution-trust.mjs")
fs.writeFileSync(
  serviceTrustModule,
  `export default {
  tenantId: "11111111-1111-4111-8111-111111111111",
  requesterDid: "did:intyga:service:test",
  approvers: { dids: ["did:intyga:owner"], resolveKey: () => "unused" },
  requirement: { requiredApprovals: 1 }
}`,
)

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
 * We deliberately do not wait for the child to exit before asking it to stop. A call that escalates to `require_approval`
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
    executionTrustModule?: string
    gatewayUrl?: string
    quietMs?: number
  } = {},
) {
  return new Promise<string>((resolve, reject) => {
    const args = [
      "--target-command",
      "cat",
      "--agent-id",
      "did:intyga:service:test",
      "--enforcement",
      opts.enforcement ?? "local-first",
    ]
    if (opts.policy) args.push("--local-policy", opts.policy)
    if (opts.agentV1Module) args.push("--agent-v1-module", opts.agentV1Module)
    else args.push("--execution-trust-module", opts.executionTrustModule ?? serviceTrustModule)
    if (opts.gatewayUrl) args.push("--gateway-url", opts.gatewayUrl)

    // `node --import tsx` rather than `npx tsx`: npx spawns tsx which spawns node, and killing the
    // top of that chain orphans the grandchild — which then holds this test's stdout pipe open and
    // stops the runner from ever exiting. One process is one process we can actually stop.
    const child = spawn(process.execPath, cliNodeArgs(args), {
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
    let finishing = false
    const finish = () => {
      if (finishing) return
      finishing = true
      clearInterval(poll)
      child.stdin.end()
      child.kill("SIGTERM")
      const force = setTimeout(() => child.kill("SIGKILL"), 3_000)
      force.unref()
      child.once("close", () => {
        clearTimeout(force)
        resolve(out)
      })
    }
    const poll = setInterval(() => {
      // Quiet only counts once something has arrived — otherwise a slow boot looks like silence and
      // every test would resolve empty in QUIET_MS.
      if (out.length > 0 && Date.now() - lastData >= (opts.quietMs ?? QUIET_MS)) return finish()
      if (Date.now() - started >= SETTLE_CAP_MS) return finish()
    }, 50)
  })
}

async function runCli(
  args: string[],
  input = "",
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, cliNodeArgs(args), {
    stdio: ["pipe", "pipe", "pipe"],
    env,
  })
  let stdout = ""
  let stderr = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  child.stderr.on("data", (data: Buffer) => {
    stderr += data.toString()
  })
  child.stdin.end(input)
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("close", resolve)
  })
  return { code, stdout, stderr }
}

function waitUntil(check: () => boolean, timeoutMs = 5_000): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs
    const poll = setInterval(() => {
      if (check()) {
        clearInterval(poll)
        resolve()
      } else if (Date.now() >= deadline) {
        clearInterval(poll)
        reject(new Error("condition timed out"))
      }
    }, 10)
  })
}

function linuxProcessRunning(pid: number): boolean {
  try {
    const fields = fs.readFileSync(`/proc/${pid}/stat`, "utf8").split(" ")
    return fields[2] !== "Z"
  } catch {
    return false
  }
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
    tenantId: "11111111-1111-4111-8111-111111111111",
    requesterDid: "did:intyga:agent:test",
    approvers: { publicKeys: ["test-placeholder"] },
    verifier: {},
    requirement: { requiredApprovals: 1 },
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
  const gateway = await approvingGateway(t)
  const out = await runProxy(
    [
      rpc("tools/call", { name: "read_report", arguments: { seq: 1 } }, 1),
      rpc("tools/call", { name: "read_report", arguments: { seq: 2 } }, 2),
      rpc("tools/call", { name: "read_report", arguments: { seq: 3 } }, 3),
    ],
    {
      policy: policyFile([{ action: "read_report", effect: "allow" }]),
      gatewayUrl: gateway.url,
      executionTrustModule: gateway.executionTrustModule,
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
async function approvingGateway(
  t: { after: (fn: () => void) => void },
  options: { status?: "APPROVED" | "DENIED"; consumeOk?: boolean } = {},
) {
  const authorizeBodies: unknown[] = []
  const entries = new Map<string, Record<string, unknown>>()
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const tenantId = "11111111-1111-4111-8111-111111111111"
  const requesterDid = "did:intyga:service:test"
  const requirement = {
    requiredApprovals: 1,
    requireHardwareKey: false,
    allowedAaguids: [],
    requesterCannotApprove: true,
    signerClass: "human",
  }
  const server = createServer((req, res) => {
    let body = ""
    req.on("data", (c: Buffer) => (body += c.toString()))
    req.on("end", () => {
      res.setHeader("content-type", "application/json")
      if (req.url === "/oauth/token") return void res.end(JSON.stringify({ access_token: "test-token" }))
      if (req.url === "/authorize/verify")
        return void res.end(JSON.stringify({ ok: options.consumeOk ?? true }))
      if (req.url === "/authorize") {
        const action = JSON.parse(body) as Record<string, unknown>
        authorizeBodies.push(action)
        const nonce = `n-${authorizeBodies.length}`
        entries.set(nonce, action)
        return void res.end(JSON.stringify({ nonce }))
      }
      const nonce = decodeURIComponent((req.url ?? "").slice("/authorize/".length))
      const action = entries.get(nonce)!
      const expiresAt = new Date(Date.now() + 120_000).toISOString()
      const canonicalPayload = canonicalIntentPayload({
        tenantId,
        target: action.target as string,
        actionType: action.actionType as string,
        display: action.actionDescription as string,
        params: action.params as Record<string, unknown>,
        requester: { did: requesterDid, attestation: null },
        requirement,
        nonce,
        expiresAt,
      })
      const receipt = {
        canonicalPayload,
        actionDescription: action.actionDescription,
        params: action.params,
        requester: { did: requesterDid, attestation: null },
        signerDid: "did:intyga:owner",
        signerPublicKey: publicKey,
        signature: crypto
          .sign("sha256", Buffer.from(canonicalPayload), { key: keys.privateKey, dsaEncoding: "ieee-p1363" })
          .toString("base64"),
        sigAlg: "ES256",
        verificationCode: "unused",
      }
      return void res.end(JSON.stringify({ status: options.status ?? "APPROVED", receipt }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  t.after(() => server.close())
  const address = server.address()
  assert.ok(address && typeof address !== "string")
  const executionTrustModule = path.join(tmp, `execution-trust-${Math.random().toString(36).slice(2)}.mjs`)
  fs.writeFileSync(
    executionTrustModule,
    `export default { tenantId: ${JSON.stringify(tenantId)}, requesterDid: ${JSON.stringify(requesterDid)}, approvers: { dids: ["did:intyga:owner"], resolveKey: (did) => (did === "did:intyga:owner" ? ${JSON.stringify(publicKey)} : null) }, requirement: { requiredApprovals: 1 } }`,
  )
  return { url: `http://127.0.0.1:${address.port}`, authorizeBodies, executionTrustModule }
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

test("JSON primitives and null are canonical protocol passthrough", async () => {
  const out = await runProxy(["null", "7", "true", JSON.stringify("ping")])
  assert.deepEqual(out.trim().split("\n"), ["null", "7", "true", '"ping"'])
})

test("startup refuses missing commands and unsafe target argument shapes", async () => {
  const missing = await runCli([])
  assert.equal(missing.code, 1)
  assert.match(missing.stderr, /target-command is required/)
  const missingValue = await runCli(["--target-command"])
  assert.equal(missingValue.code, 1)
  assert.match(missingValue.stderr, /--target-command requires a value/)
  for (const targetArgs of ['{"shell":true}', "not-json", '["ok",1]']) {
    const result = await runCli(["--target-command", "cat", "--target-args", targetArgs])
    assert.equal(result.code, 1)
    assert.match(result.stderr, /target-args must be a JSON array of strings/)
  }
})

test("startup refuses absent, ambiguous, and malformed RP trust", async () => {
  const base = ["--target-command", "cat"]
  const absent = await runCli(base)
  assert.equal(absent.code, 1)
  assert.match(absent.stderr, /Configure exactly one/)
  const malformed = path.join(tmp, "malformed-trust.mjs")
  fs.writeFileSync(malformed, "export default { tenantId: '', requesterDid: 42 }")
  const invalid = await runCli([...base, "--execution-trust-module", malformed])
  assert.equal(invalid.code, 1)
  assert.match(invalid.stderr, /tenantId must be a non-empty RP-owned string/)
  const agentModule = path.join(tmp, "valid-agent-v1.mjs")
  fs.writeFileSync(
    agentModule,
    `export default { tenantId: "11111111-1111-4111-8111-111111111111", requesterDid: "did:intyga:agent:test", approvers: { publicKeys: ["test-placeholder"] }, verifier: {}, requirement: { requiredApprovals: 1 }, prepare: async () => ({}), liveConfig: async () => ({}), readState: async () => ({}), reserve: async () => false }`,
  )
  const ambiguous = await runCli([
    ...base,
    "--execution-trust-module",
    serviceTrustModule,
    "--agent-v1-module",
    agentModule,
  ])
  assert.equal(ambiguous.code, 1)
  assert.match(ambiguous.stderr, /Configure exactly one/)
})

test("startup warns about argv secrets and an unreadable optional policy", async () => {
  const result = await runCli([
    "--target-command",
    "true",
    "--execution-trust-module",
    serviceTrustModule,
    "--client-secret",
    "unsafe-argv-secret",
    "--local-policy",
    path.join(tmp, "does-not-exist.json"),
  ])
  assert.equal(result.code, 0)
  assert.match(result.stderr, /Failed to read local policy file/)
  assert.match(result.stderr, /client-secret exposes the secret in argv/)
})

test("explicit flags and environment-only configuration both start the shipped CLI", async () => {
  const policy = policyFile([{ action: "none", effect: "deny" }])
  const flags = await runCli([
    "--target-command",
    "true",
    "--target-args",
    "[]",
    "--gateway-url",
    "http://127.0.0.1:8787",
    "--client-id",
    "client",
    "--agent-id",
    "did:intyga:service:test",
    "--target",
    "flag-target",
    "--enforcement",
    "gateway-enforced",
    "--local-policy",
    policy,
    "--execution-trust-module",
    serviceTrustModule,
  ])
  assert.equal(flags.code, 0)

  const envOnly = await runCli(["--target-command", "true"], "", {
    ...process.env,
    INTYGA_GATEWAY_URL: "http://127.0.0.1:8787",
    INTYGA_CLIENT_ID: "client",
    INTYGA_AGENT_ID: "did:intyga:service:test",
    INTYGA_TARGET: "env-target",
    INTYGA_EXECUTION_TRUST_MODULE: serviceTrustModule,
  })
  assert.equal(envOnly.code, 0)
})

test("gateway denial and failed consumption never reach the target", async (t) => {
  for (const [options, refusal] of [
    [{ status: "DENIED" as const }, /Security Violation/],
    [{ consumeOk: false }, /Gateway Error: Approval could not be consumed/],
  ] as const) {
    const gateway = await approvingGateway(t, options)
    const out = await runProxy([rpc("tools/call", { name: "transfer", arguments: { amount: 9 } })], {
      gatewayUrl: gateway.url,
      executionTrustModule: gateway.executionTrustModule,
    })
    assert.doesNotMatch(out, /"method":"tools\/call"/)
    assert.match(out, refusal)
  }
})

test("SIGTERM cancels an in-flight approval and drops queued calls before consume or execution", async (t) => {
  let authorizes = 0
  let consumes = 0
  const gateway = createServer((req, res) => {
    req.resume()
    res.setHeader("content-type", "application/json")
    if (req.url === "/oauth/token") return void res.end(JSON.stringify({ access_token: "tok" }))
    if (req.url === "/authorize") {
      authorizes++
      return void res.end(JSON.stringify({ nonce: `pending-${authorizes}` }))
    }
    if (req.url === "/authorize/verify") {
      consumes++
      return void res.end(JSON.stringify({ ok: true }))
    }
    return void res.end(JSON.stringify({ status: "PENDING" }))
  })
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve))
  t.after(() => gateway.close())
  const address = gateway.address()
  assert.ok(address && typeof address !== "string")
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      "cat",
      "--execution-trust-module",
      serviceTrustModule,
      "--gateway-url",
      `http://127.0.0.1:${address.port}`,
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  let stdout = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  child.stdin.write(`${rpc("tools/call", { name: "first", arguments: {} }, 1)}\n`)
  child.stdin.write(`${rpc("tools/call", { name: "second", arguments: {} }, 2)}\n`)
  await waitUntil(() => authorizes === 1)
  const stoppedAt = Date.now()
  child.kill("SIGTERM")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("close", resolve)
  })
  assert.equal(code, 0)
  assert.ok(Date.now() - stoppedAt < 4_000)
  assert.equal(authorizes, 1)
  assert.equal(consumes, 0)
  assert.doesNotMatch(stdout, /"method":"tools\/call"/)
})

test("hard deadline exits when an RP adapter ignores cancellation forever", async (t) => {
  let tokens = 0
  let authorizes = 0
  let consumes = 0
  const gateway = createServer((req, res) => {
    req.resume()
    res.setHeader("content-type", "application/json")
    if (req.url === "/oauth/token") {
      tokens++
      return void res.end(JSON.stringify({ access_token: "tok" }))
    }
    if (req.url === "/authorize") authorizes++
    if (req.url === "/authorize/verify") consumes++
    return void res.end(JSON.stringify({ status: "PENDING" }))
  })
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve))
  t.after(() => gateway.close())
  const address = gateway.address()
  assert.ok(address && typeof address !== "string")
  const stuckRuntime = path.join(tmp, "stuck-agent-v1.mjs")
  fs.writeFileSync(
    stuckRuntime,
    `export default { tenantId: "11111111-1111-4111-8111-111111111111", requesterDid: "did:intyga:agent:test", approvers: { publicKeys: ["placeholder"] }, requirement: { requiredApprovals: 1 }, verifier: {}, prepare: () => new Promise(() => {}), liveConfig: async () => ({}), readState: async () => ({}), reserve: async () => false }`,
  )
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      "cat",
      "--agent-v1-module",
      stuckRuntime,
      "--local-policy",
      policyFile([{ action: "first-denied", effect: "deny" }]),
      "--gateway-url",
      `http://127.0.0.1:${address.port}`,
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  let stdout = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  // The first queue link completes locally; the second enters an RP adapter that never settles.
  // The hard deadline must remain armed after the earlier link's finally handler runs.
  child.stdin.write(`${rpc("tools/call", { name: "first-denied", arguments: {} }, 1)}\n`)
  child.stdin.write(`${rpc("tools/call", { name: "stuck", arguments: {} }, 2)}\n`)
  await waitUntil(() => tokens === 1)
  const stoppedAt = Date.now()
  child.kill("SIGTERM")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("close", resolve)
  })
  assert.equal(code, 0)
  assert.ok(Date.now() - stoppedAt >= 2_500 && Date.now() - stoppedAt < 4_000)
  assert.equal(authorizes, 0)
  assert.equal(consumes, 0)
  assert.doesNotMatch(stdout, /"method":"tools\/call"/)
})

test("a delayed RP adapter settles after target exit and clears the hard deadline", async (t) => {
  let tokens = 0
  const gateway = createServer((req, res) => {
    req.resume()
    res.setHeader("content-type", "application/json")
    if (req.url === "/oauth/token") {
      tokens++
      return void res.end(JSON.stringify({ access_token: "tok" }))
    }
    return void res.end(JSON.stringify({ status: "PENDING" }))
  })
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve))
  t.after(() => gateway.close())
  const address = gateway.address()
  assert.ok(address && typeof address !== "string")
  const runtime = path.join(tmp, "delayed-agent-v1.mjs")
  fs.writeFileSync(
    runtime,
    `export default { tenantId: "11111111-1111-4111-8111-111111111111", requesterDid: "did:intyga:agent:test", approvers: { publicKeys: ["placeholder"] }, requirement: { requiredApprovals: 1 }, verifier: {}, prepare: () => new Promise(resolve => setTimeout(() => resolve({}), 500)), liveConfig: async () => ({}), readState: async () => ({}), reserve: async () => false }`,
  )
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      "cat",
      "--agent-v1-module",
      runtime,
      "--gateway-url",
      `http://127.0.0.1:${address.port}`,
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  child.stdin.write(`${rpc("tools/call", { name: "delayed", arguments: {} })}\n`)
  await waitUntil(() => tokens === 1)
  const stoppedAt = Date.now()
  child.kill("SIGTERM")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("exit", resolve)
  })
  assert.equal(code, 0)
  // The process-group KILL escalation remains referenced until 2s even when target stdout closes;
  // the separate 3s hard parent deadline is still cleared after the adapter settles.
  assert.ok(Date.now() - stoppedAt < 2_800)
})

test("shutdown kills a target that ignores SIGTERM and exits within the hard deadline", async () => {
  const grandchildPidFile = path.join(tmp, `grandchild-${crypto.randomUUID()}.pid`)
  const started = Date.now()
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      process.execPath,
      "--target-args",
      JSON.stringify([
        "-e",
        `const{spawn}=require("node:child_process");const fs=require("node:fs");const grandchild=spawn(process.execPath,["-e","process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:"ignore"});fs.writeFileSync(${JSON.stringify(grandchildPidFile)},String(grandchild.pid));process.on("SIGTERM",()=>{});setInterval(()=>{},1000)`,
      ]),
      "--execution-trust-module",
      serviceTrustModule,
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  await waitUntil(() => fs.existsSync(grandchildPidFile))
  const grandchildPid = Number(fs.readFileSync(grandchildPidFile, "utf8"))
  child.kill("SIGTERM")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("exit", resolve)
  })
  assert.equal(code, 0)
  assert.ok(Date.now() - started < 4_000)
  await waitUntil(() => !linuxProcessRunning(grandchildPid))
  assert.equal(linuxProcessRunning(grandchildPid), false)
})

test("a launcher that exits first still has its surviving process-group descendants killed", {
  skip: process.platform === "win32",
}, async () => {
  const grandchildPidFile = path.join(tmp, `departed-launcher-${crypto.randomUUID()}.pid`)
  // The descendant deliberately closes every stdio pipe. EOF must not be mistaken for proof that
  // the process group is gone: it ignores TERM and therefore still requires the KILL escalation.
  const launcher = `const{spawn}=require("node:child_process");const fs=require("node:fs");const child=spawn(process.execPath,["-e","process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:"ignore"});child.unref();fs.writeFileSync(${JSON.stringify(grandchildPidFile)},String(child.pid))`
  const started = Date.now()
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      process.execPath,
      "--target-args",
      JSON.stringify(["-e", launcher]),
      "--execution-trust-module",
      serviceTrustModule,
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  const exited = new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("exit", resolve)
  })
  await waitUntil(() => fs.existsSync(grandchildPidFile))
  const grandchildPid = Number(fs.readFileSync(grandchildPidFile, "utf8"))
  const code = await exited
  assert.equal(code, 0)
  assert.ok(Date.now() - started < 4_000)
  await waitUntil(() => !linuxProcessRunning(grandchildPid))
  assert.equal(linuxProcessRunning(grandchildPid), false)
})

test("SIGINT shuts down the proxy and its target cleanly", async () => {
  const child = spawn(
    process.execPath,
    cliNodeArgs(["--target-command", "cat", "--execution-trust-module", serviceTrustModule]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  child.stdin.write(`${rpc("initialize")}\n`)
  let stdout = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  await waitUntil(() => stdout.includes('"method":"initialize"'))
  child.kill("SIGINT")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("close", resolve)
  })
  assert.equal(code, 0)
})

test("back-to-back termination signals are idempotent", async () => {
  const child = spawn(
    process.execPath,
    cliNodeArgs(["--target-command", "cat", "--execution-trust-module", serviceTrustModule]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  let stdout = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  child.stdin.write(`${rpc("initialize")}\n`)
  await waitUntil(() => stdout.includes('"method":"initialize"'))
  child.kill("SIGTERM")
  child.kill("SIGINT")
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject)
    child.once("exit", resolve)
  })
  assert.equal(code, 0)
})

test("unterminated child output is drained before a normal target exit", async () => {
  const result = await runCli([
    "--target-command",
    process.execPath,
    "--target-args",
    JSON.stringify(["-e", "process.stdout.write('partial')"]),
    "--execution-trust-module",
    serviceTrustModule,
  ])
  assert.equal(result.code, 0)
  assert.equal(result.stdout, "partial")
})

test("shutdown never appends a late gate refusal to an unterminated target tail", async (t) => {
  const gateway = createServer((req, res) => {
    req.resume()
    res.setHeader("content-type", "application/json")
    if (req.url === "/oauth/token") return void res.end(JSON.stringify({ access_token: "tok" }))
    return void res.end(JSON.stringify({ status: "PENDING" }))
  })
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve))
  t.after(() => gateway.close())
  const address = gateway.address()
  assert.ok(address && typeof address !== "string")
  const rejectingRuntime = path.join(tmp, `rejecting-agent-v1-${crypto.randomUUID()}.mjs`)
  fs.writeFileSync(
    rejectingRuntime,
    `export default { tenantId: "11111111-1111-4111-8111-111111111111", requesterDid: "did:intyga:agent:test", approvers: { publicKeys: ["placeholder"] }, requirement: { requiredApprovals: 1 }, verifier: {}, prepare: () => new Promise((_, reject) => setTimeout(() => reject(new Error("late failure")), 250)), liveConfig: async () => ({}), readState: async () => ({}), reserve: async () => false }`,
  )
  const result = await runCli(
    [
      "--target-command",
      process.execPath,
      "--target-args",
      JSON.stringify(["-e", "process.stdout.write('partial');setTimeout(()=>process.exit(0),100)"]),
      "--agent-v1-module",
      rejectingRuntime,
      "--gateway-url",
      `http://127.0.0.1:${address.port}`,
    ],
    `${rpc("tools/call", { name: "late", arguments: {} })}\n`,
  )
  assert.equal(result.code, 0)
  assert.equal(result.stdout, "partial")
})

test("a target terminated by signal gives the proxy a failing supervisor status", async () => {
  const result = await runCli([
    "--target-command",
    process.execPath,
    "--target-args",
    JSON.stringify(["-e", "process.kill(process.pid,'SIGTERM')"]),
    "--execution-trust-module",
    serviceTrustModule,
  ])
  assert.equal(result.code, 1)
})

test("split UTF-8 output drains on immediate target exit and cannot interleave a refusal", async () => {
  const target = `let tail="";process.stdin.setEncoding("utf8");process.stdin.on("data",d=>{tail+=d;let i;while((i=tail.indexOf("\\n"))>=0){const line=tail.slice(0,i);tail=tail.slice(i+1);if(!line)continue;const request=JSON.parse(line);const bytes=Buffer.from(JSON.stringify({jsonrpc:"2.0",id:request.id,result:{text:"x".repeat(70000)+"😀"}})+"\\n");const emoji=bytes.indexOf(Buffer.from("😀"));process.stdout.write(bytes.subarray(0,emoji+1));setTimeout(()=>process.stdout.write(bytes.subarray(emoji+1),()=>process.exit(0)),25)}})`
  const child = spawn(
    process.execPath,
    cliNodeArgs([
      "--target-command",
      process.execPath,
      "--target-args",
      JSON.stringify(["-e", target]),
      "--execution-trust-module",
      serviceTrustModule,
      "--local-policy",
      policyFile([{ action: "blocked", effect: "deny" }]),
    ]),
    { stdio: ["pipe", "pipe", "pipe"] },
  )
  let stdout = ""
  child.stdout.on("data", (data: Buffer) => {
    stdout += data.toString()
  })
  child.stdin.write(`${rpc("initialize", undefined, 1)}\n`)
  child.stdin.write(`${rpc("tools/call", { name: "blocked", arguments: {} }, 2)}\n`)
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject)
    child.once("close", () => resolve())
  })
  const lines = stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>)
  assert.equal(lines.length, 2)
  assert.match(stdout, /😀/)
  assert.doesNotMatch(stdout, /�/)
  assert.ok(lines.some((line) => "error" in line))
  assert.ok(lines.some((line) => "result" in line))
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
    executionTrustModule: gateway.executionTrustModule,
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
  const out = await runProxy(calls, {
    gatewayUrl: gateway.url,
    executionTrustModule: gateway.executionTrustModule,
    quietMs: 2_500,
  })
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
  const child = spawn(
    process.execPath,
    cliNodeArgs(["--target-command", "cat", "--gateway-url", "http://gw.example"]),
    { stdio: ["ignore", "pipe", "pipe"] },
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
