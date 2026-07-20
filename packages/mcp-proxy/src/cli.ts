#!/usr/bin/env node

import { spawn } from "node:child_process"
import fs from "node:fs"
import readline from "node:readline"
import { evaluatePolicy } from "@sakra-trust/mcp-sdk"

// Simple CLI arguments parser
const args = process.argv.slice(2)
const gatewayUrl = getArg("--gateway-url") || "http://localhost:8787"
const clientId = getArg("--client-id") || ""
const clientSecret = getArg("--client-secret") || ""
const _agentId = getArg("--agent-id") || ""
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

rl.on("line", (line) => {
  processMessage(line).catch((err) => {
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
      try {
        // Authenticate
        const tokenRes = await fetch(`${gatewayUrl}/oauth/token`, {
          method: "POST",
          headers: {
            Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: "grant_type=client_credentials",
        })

        if (!tokenRes.ok) {
          throw new Error(`Authentication failed (${tokenRes.status})`)
        }

        const { access_token } = (await tokenRes.json()) as {
          access_token: string
        }

        // Request challenge
        const challengeRes = await fetch(`${gatewayUrl}/action/request`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            actionType: name,
            params: handlerArgs,
            actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
          }),
        })

        if (!challengeRes.ok) {
          const errBody = (await challengeRes.json().catch(() => ({ error: undefined }))) as {
            error?: string
          }
          throw new Error(errBody.error ?? `Failed challenge creation (${challengeRes.status})`)
        }

        const { nonce } = (await challengeRes.json()) as { nonce: string }

        // Poll status
        let status = "PENDING"
        const pollIntervalMs = 2000
        const maxPollAttempts = 60
        let attempts = 0

        while (status === "PENDING" && attempts < maxPollAttempts) {
          await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
          attempts++

          const checkRes = await fetch(`${gatewayUrl}/action/status/${nonce}`, {
            headers: {
              Authorization: `Bearer ${access_token}`,
            },
          })

          if (checkRes.ok) {
            const checkData = (await checkRes.json()) as { status: string }
            status = checkData.status
          }
        }

        if (status === "APPROVED") {
          // Consume approved challenge
          const consumeRes = await fetch(`${gatewayUrl}/action/consume`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              nonce,
              actionType: name,
              params: handlerArgs,
            }),
          })

          if (!consumeRes.ok) {
            throw new Error(`Failed to consume signature challenge`)
          }

          // Forward to target tool
          if (child.stdin) {
            child.stdin.write(`${line}\n`)
          }
        } else {
          const response = {
            jsonrpc: "2.0",
            id,
            error: {
              code: -32603,
              message: `Security Violation: Action '${name}' was rejected or timed out (status: ${status}).`,
            },
          }
          process.stdout.write(`${JSON.stringify(response)}\n`)
        }
      } catch (err) {
        const response = {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32603,
            message: `SÄKRA Gateway Error: ${(err as Error).message}`,
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
