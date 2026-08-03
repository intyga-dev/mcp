// The proxy sits in the stdio path between an MCP client and a real MCP server, so its contract is
// only observable end to end: feed JSON-RPC in on stdin, watch what reaches the target versus what
// gets refused. These drive the real CLI as a subprocess with `cat` standing in for the target
// server — anything `cat` echoes back is something the proxy chose to forward.

import assert from "node:assert/strict"
import { spawn } from "node:child_process"
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
function runProxy(lines: string[], opts: { policy?: string; enforcement?: string } = {}) {
  return new Promise<string>((resolve, reject) => {
    const args = [CLI, "--target-command", "cat", "--enforcement", opts.enforcement ?? "local-first"]
    if (opts.policy) args.push("--local-policy", opts.policy)

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
      if (out.length > 0 && Date.now() - lastData >= QUIET_MS) return finish()
      if (Date.now() - started >= SETTLE_CAP_MS) return finish()
    }, 50)
  })
}

test("an allowed tool call is forwarded to the target server", async () => {
  const line = rpc("tools/call", { name: "read_report", arguments: {} })
  const out = await runProxy([line], {
    policy: policyFile([{ action: "read_report", effect: "allow" }]),
  })
  // `cat` echoed it, so the proxy passed it through.
  assert.match(out, /"method":"tools\/call"/)
  assert.doesNotMatch(out, /Security Violation/)
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

test("tool calls reach the target in the order they were sent", async () => {
  // Bypassing the queue is only safe for non-tool traffic — tool calls must stay ordered relative to
  // each other, since two mutating actions arriving out of order is a correctness bug.
  //
  // Note this checks ordering, not blocking. Proving that a *pending* approval holds the next tool
  // call back needs a gateway that keeps a challenge open; with none reachable the first call fails
  // fast, so that half of the contract is only exercised against a live gateway (see e2e-roundtrip).
  const out = await runProxy(
    [
      rpc("tools/call", { name: "read_report", arguments: { seq: 1 } }, 1),
      rpc("tools/call", { name: "read_report", arguments: { seq: 2 } }, 2),
      rpc("tools/call", { name: "read_report", arguments: { seq: 3 } }, 3),
    ],
    { policy: policyFile([{ action: "read_report", effect: "allow" }]) },
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
