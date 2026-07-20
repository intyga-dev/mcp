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
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sakra-proxy-test-"))

function policyFile(rules: unknown): string {
  const file = path.join(tmp, `policy-${Math.random().toString(36).slice(2)}.json`)
  fs.writeFileSync(file, JSON.stringify({ rules }))
  return file
}

const rpc = (method: string, params?: unknown, id = 1) =>
  JSON.stringify({ jsonrpc: "2.0", id, method, params })

const SETTLE_MS = 3_000

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
    child.stdout.on("data", (d: Buffer) => {
      out += d.toString()
    })
    child.on("error", reject)

    for (const line of lines) child.stdin.write(`${line}\n`)
    setTimeout(() => {
      child.kill("SIGKILL")
      child.stdout.destroy()
      child.stdin.destroy()
      resolve(out)
    }, SETTLE_MS)
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

test("a non-JSON line is passed through rather than dropped", async () => {
  // Framing the proxy doesn't understand is not its to swallow — the target server decides.
  const out = await runProxy(["this is not json"], {
    policy: policyFile([{ action: "x", effect: "deny" }]),
  })
  assert.match(out, /this is not json/)
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
