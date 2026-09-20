#!/usr/bin/env node

import { spawn } from "node:child_process"
import fs from "node:fs"
import readline from "node:readline"
import { evaluatePolicy, requestApproval, type AgentV1Runtime } from "@intyga/mcp-sdk"
import { pathToFileURL } from "node:url"

// Simple CLI arguments parser
const args = process.argv.slice(2)
const gatewayUrl = getArg("--gateway-url") || process.env.INTYGA_GATEWAY_URL || "http://localhost:8787"
const clientId = getArg("--client-id") || process.env.INTYGA_CLIENT_ID || ""
const clientSecret = getArg("--client-secret") || process.env.INTYGA_CLIENT_SECRET || ""
const agentId = getArg("--agent-id") || process.env.INTYGA_AGENT_ID || ""
// The relying party this proxy approves FOR (DIV §3 Invariant 5). Falls back to the agent identity
// this process already asserts — never to the gateway's `"global"` default, which binds no
// environment and makes an approval raised here replayable at every other RP in the tenant.
const approvalTarget = getArg("--target") || process.env.INTYGA_TARGET || agentId
const enforcement = getArg("--enforcement") || "local-first"
const localPolicyPath = getArg("--local-policy") || ""
const targetCommand = getArg("--target-command") || ""
const targetArgsStr = getArg("--target-args") || "[]"
const agentV1Module = getArg("--agent-v1-module") || process.env.INTYGA_AGENT_V1_MODULE || ""

function getArg(flag: string): string | null {
  const index = args.indexOf(flag)
  if (index !== -1 && index + 1 < args.length) {
    return args[index + 1] ?? null
  }
  return null
}

if (!targetCommand) {
  console.error("Error: --target-command is required")
  process.exit(1)
}

let localPolicyJson = ""
if (localPolicyPath) {
  try {
    localPolicyJson = fs.readFileSync(localPolicyPath, "utf8")
  } catch (err) {
    console.error(`Warning: Failed to read local policy file: ${(err as Error).message}`)
  }
}

// Parse target arguments JSON array. Validated rather than cast: Node's `normalizeSpawnArguments`
// treats a non-array object in the args position as the *options* object, so `--target-args
// '{"shell":true}'` would turn --target-command into a shell string. Refuse instead of guessing.
let targetArgs: string[] = []
try {
  const parsed: unknown = JSON.parse(targetArgsStr)
  if (!Array.isArray(parsed) || !parsed.every((a) => typeof a === "string")) {
    throw new Error("expected a JSON array of strings")
  }
  targetArgs = parsed
} catch (err) {
  console.error(`Error: --target-args must be a JSON array of strings: ${(err as Error).message}`)
  process.exit(1)
}

// The module belongs to the relying party, not the MCP caller or wrapped server. It owns the
// live-config source and atomic session/nonce/budget store required by the v1 execution PEP.
let agentV1: AgentV1Runtime | undefined
if (agentV1Module) {
  const candidate: unknown = (await import(pathToFileURL(fs.realpathSync(agentV1Module)).href)).default
  if (
    !candidate ||
    typeof candidate !== "object" ||
    !["prepare", "liveConfig", "readState", "reserve"].every(
      (key) => typeof (candidate as Record<string, unknown>)[key] === "function",
    ) ||
    typeof (candidate as Record<string, unknown>).requesterDid !== "string" ||
    !(candidate as Record<string, unknown>).approvers ||
    !(candidate as Record<string, unknown>).verifier
  )
    throw new Error("--agent-v1-module must export an RP-owned AgentV1Runtime")
  agentV1 = candidate as AgentV1Runtime
}

if (getArg("--client-secret")) {
  // argv is world-readable via `ps`, and the target server can read it from /proc/<ppid>/cmdline —
  // the one process we are here to distrust.
  console.error("Warning: --client-secret exposes the secret in argv. Use INTYGA_CLIENT_SECRET.")
}

// The target server is third-party code this proxy exists to mediate. It has no business holding the
// credentials that raise approval challenges in the operator's name, so INTYGA_* is stripped from
// what it inherits. Everything else is passed through — a target server legitimately needs its own
// API keys, PATH and HOME.
const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("INTYGA_")))

// Spawn the target MCP server child process
const child = spawn(targetCommand, targetArgs, {
  stdio: ["pipe", "pipe", "inherit"],
  env: childEnv,
})

child.on("exit", (code) => {
  process.exit(code ?? 0)
})

// Setup stdio interfaces
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
})

// Both the target server's replies and the proxy's own refusals go to the same stdout, which is the
// protocol channel. A reply larger than a pipe buffer arrives in several chunks, and a refusal
// resolving on another turn of the event loop could land between two of them and split the line.
// Holding partial child output until it is newline-terminated means a proxy message can only ever be
// written at a line boundary.
let childStdoutTail = ""

function writeChildOutput(data: Buffer): void {
  const text = childStdoutTail + data.toString()
  const lastNewline = text.lastIndexOf("\n")
  if (lastNewline === -1) {
    childStdoutTail = text
    return
  }
  childStdoutTail = text.slice(lastNewline + 1)
  process.stdout.write(text.slice(0, lastNewline + 1))
}

if (child.stdout) {
  child.stdout.on("data", writeChildOutput)
}

function writeError(id: unknown, code: number, message: string): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } })}\n`)
}

function forwardToChild(payload: string): void {
  child.stdin?.write(`${payload}\n`)
}

// Gated tool calls run one at a time, in FIFO order: two mutating calls must not be reordered, and
// serialising them also caps how many approval prompts a runaway agent can raise at once.
let messageQueue: Promise<void> = Promise.resolve()

interface ToolCall {
  id: unknown
  name: string
  args: Record<string, unknown>
}

type Classification =
  | { kind: "gate"; call: ToolCall; canonical: string }
  | { kind: "passthrough"; payload: string }
  | { kind: "reject"; id: unknown; code: number; message: string }

/**
 * Decide what a line from the client is, once. Everything downstream works off this result rather
 * than re-parsing, so the proxy and the target server cannot disagree about what a message says.
 *
 * The client here is the agent, which is precisely the party this proxy distrusts — so a
 * classification that depends on the two ends parsing identically is not a classification.
 * Forwarded messages are re-serialized from what we parsed for the same reason: a duplicate
 * `"method"` key resolves to the last occurrence in JS and the first in some other parsers, so
 * `{"method":"tools/call","method":"ping"}` used to read as `ping` here and as a tool call to a
 * target server that disagreed. Re-serializing emits exactly one of each key.
 */
function classify(line: string): Classification {
  let json: unknown
  try {
    json = JSON.parse(line)
  } catch {
    // FAIL CLOSED. The comment here used to claim "a line that is not JSON cannot be a `tools/call`
    // under any JSON parser, so passing it on opens nothing." That is only true for parsers as
    // strict as V8's, and this proxy exists to wrap third-party servers whose parser it does not
    // control — the same reasoning already applied to batches below.
    //
    // Measured: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_prod_db",
    // "arguments":{"x":NaN}}}` throws SyntaxError in Node and parses cleanly in Python's stdlib
    // `json.loads` (NaN/Infinity are a documented CPython extension), yielding method `tools/call`.
    // Forwarding it meant the policy check, the approval and the audit entry were all skipped while
    // the target executed the tool. `Infinity`, trailing commas, comments and single quotes all give
    // the same shape against a target with a more lenient parser.
    //
    // A proxy must never forward bytes it did not understand. -32700 is also the correct JSON-RPC
    // response for a parse error.
    return {
      kind: "reject",
      id: null,
      code: -32700,
      message: "Intyga Proxy: message is not valid JSON and was refused rather than forwarded.",
    }
  }

  if (Array.isArray(json)) {
    // A JSON-RPC batch has no top-level `.method`, so it used to classify as non-tool traffic and go
    // straight to the target — carrying any number of ungated `tools/call` entries. MCP removed
    // batching in revision 2025-06-18; refusing is both spec-current and the only safe reading,
    // since the proxy cannot know whether the target still honours them.
    return {
      kind: "reject",
      id: null,
      code: -32600,
      message: "Intyga Proxy: JSON-RPC batches are not supported. Send one request per line.",
    }
  }

  if (typeof json !== "object" || json === null) {
    return { kind: "passthrough", payload: JSON.stringify(json) }
  }

  const message = json as { method?: unknown; id?: unknown; params?: unknown }
  const canonical = JSON.stringify(message)

  if (message.method !== "tools/call") return { kind: "passthrough", payload: canonical }

  const params =
    typeof message.params === "object" && message.params !== null
      ? (message.params as { name?: unknown; arguments?: unknown })
      : {}
  const rawArgs = params.arguments
  return {
    kind: "gate",
    canonical,
    call: {
      id: message.id,
      name: typeof params.name === "string" ? params.name : "",
      args:
        typeof rawArgs === "object" && rawArgs !== null && !Array.isArray(rawArgs)
          ? (rawArgs as Record<string, unknown>)
          : {},
    },
  }
}

rl.on("line", (line) => {
  const classified = classify(line)

  if (classified.kind === "reject") {
    writeError(classified.id, classified.code, classified.message)
    return
  }

  // Everything that is NOT a tool call bypasses the queue. A pending approval can block for up to
  // two minutes, and clients time individual requests out far sooner than that — queueing
  // `initialize`, `ping` and the `*/list` methods behind a human decision would let the client
  // conclude the server is dead and tear down the session, abandoning the very approval it was
  // waiting for. None of these mutate anything, so letting them overtake a pending call is safe.
  if (classified.kind === "passthrough") {
    forwardToChild(classified.payload)
    return
  }

  const { call, canonical } = classified
  messageQueue = messageQueue
    .then(() => processToolCall(call, canonical))
    .catch((err: unknown) => {
      // processToolCall handles its own failures; this is the backstop for one that escapes. It
      // refuses — it must never fall back to forwarding, which is what the old catch did.
      console.error("[Intyga Proxy] Error processing message:", err)
      writeError(call.id, -32603, `Intyga Proxy error: ${(err as Error).message}`)
    })
})

async function processToolCall(call: ToolCall, canonical: string): Promise<void> {
  const { id, name, args: handlerArgs } = call
  try {
    // 1. Evaluate policy — the same gate the in-process wrapper uses, so the two enforcement paths
    //    cannot reach different verdicts for the same call.
    const decision = evaluatePolicy(name, handlerArgs, {
      enforcement: enforcement as "local-first" | "gateway-enforced",
      localPolicyJson,
    })

    if (decision === "deny") {
      writeError(id, -32603, `Security Violation: Action '${name}' is denied by Intyga policy.`)
      return
    }

    // 2. Request Human approval
    const outcome = await requestApproval({
      gatewayUrl,
      clientId,
      clientSecret,
      target: approvalTarget,
      actionType: name,
      params: handlerArgs,
      actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
      agentV1,
    })

    if (outcome.outcome === "approved") {
      // The canonical form, not the original line: the target executes exactly the parameters the
      // human was shown and the policy was evaluated against.
      forwardToChild(canonical)
      return
    }

    if (outcome.outcome === "refused") {
      writeError(id, -32603, `Security Violation: ${outcome.reason}`)
      return
    }

    writeError(id, -32603, `Intyga Gateway Error: ${outcome.reason}`)
  } catch (err) {
    // Fail closed. This catch used to write the original line to the target server, so any throw in
    // the gate — a malformed policy manifest was enough — forwarded the tool call ungated, with no
    // error to the client and no log. A gate that opens when it breaks is worse than no gate.
    console.error("[Intyga Proxy] Gate failed, refusing:", err)
    writeError(id, -32603, `Intyga Proxy error: the approval gate failed, so the call was refused.`)
  }
}
