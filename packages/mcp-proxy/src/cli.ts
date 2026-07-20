#!/usr/bin/env node

import { spawn } from "node:child_process"
import fs from "node:fs"
import readline from "node:readline"
import { evaluatePolicy, requestApproval } from "@sakra-trust/mcp-sdk"

// Simple CLI arguments parser
const args = process.argv.slice(2)
const gatewayUrl = getArg("--gateway-url") || process.env.SAKRA_GATEWAY_URL || "http://localhost:8787"
const clientId = getArg("--client-id") || process.env.SAKRA_CLIENT_ID || ""
const clientSecret = getArg("--client-secret") || process.env.SAKRA_CLIENT_SECRET || ""
const _agentId = getArg("--agent-id") || process.env.SAKRA_AGENT_ID || ""
const enforcement = getArg("--enforcement") || "local-first"
const localPolicyPath = getArg("--local-policy") || ""
const targetCommand = getArg("--target-command") || ""
const targetArgsStr = getArg("--target-args") || "[]"

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

// Parse target arguments JSON array
let targetArgs: string[] = []
try {
  targetArgs = JSON.parse(targetArgsStr) as string[]
} catch {
  targetArgs = []
}

// Spawn the target MCP server child process
const child = spawn(targetCommand, targetArgs, {
  stdio: ["pipe", "pipe", "inherit"],
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

if (child.stdout) {
  child.stdout.on("data", (data: Buffer) => {
    process.stdout.write(data)
  })
}

// Process messages sequentially in FIFO order to preserve JSON-RPC message ordering and bound in-flight approvals.
let messageQueue: Promise<void> = Promise.resolve()

rl.on("line", (line) => {
  messageQueue = messageQueue
    .then(() => processMessage(line))
    .catch((err) => {
      console.error("[SÄKRA Proxy] Error processing message:", err)
    })
})

async function processMessage(line: string) {
  try {
    const json = JSON.parse(line) as {
      method?: string
      id?: unknown
      params?: { name?: string; arguments?: Record<string, unknown> }
    }

    if (json.method === "tools/call") {
      const name = json.params?.name || ""
      const handlerArgs = json.params?.arguments || {}
      const id = json.id

      // 1. Evaluate policy — the same gate the in-process wrapper uses, so the two enforcement paths
      //    cannot reach different verdicts for the same call.
      const decision = evaluatePolicy(name, handlerArgs, {
        enforcement: enforcement as "local-first" | "gateway-enforced",
        localPolicyJson,
      })

      if (decision === "allow") {
        if (child.stdin) {
          child.stdin.write(`${line}\n`)
        }
        return
      }

      if (decision === "deny") {
        const response = {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32603,
            message: `Security Violation: Action '${name}' is denied by SÄKRA policy.`,
          },
        }
        process.stdout.write(`${JSON.stringify(response)}\n`)
        return
      }

      // 2. Request Human approval
      const outcome = await requestApproval({
        gatewayUrl,
        clientId,
        clientSecret,
        actionType: name,
        params: handlerArgs,
        actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
      })

      if (outcome.outcome === "approved") {
        if (child.stdin) {
          child.stdin.write(`${line}\n`)
        }
      } else if (outcome.outcome === "refused") {
        const response = {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32603,
            message: `Security Violation: ${outcome.reason}`,
          },
        }
        process.stdout.write(`${JSON.stringify(response)}\n`)
      } else {
        const response = {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32603,
            message: `SÄKRA Gateway Error: ${outcome.reason}`,
          },
        }
        process.stdout.write(`${JSON.stringify(response)}\n`)
      }
    } else {
      // Pass through all other messages
      if (child.stdin) {
        child.stdin.write(`${line}\n`)
      }
    }
  } catch {
    if (child.stdin) {
      child.stdin.write(`${line}\n`)
    }
  }
}
