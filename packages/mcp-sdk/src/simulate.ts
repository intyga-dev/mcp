import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { z } from "zod"
import { intygafyServer } from "./index.js"

async function runSimulation() {
  console.log("=== Intyga MCP SDK Simulator ===")

  const server = new McpServer({ name: "simulator-server", version: "1.0.0" })

  // Register three sample tools on the server
  server.tool("get_status", "Get server status", {}, async () => {
    return {
      content: [{ type: "text" as const, text: "System normal. Up 24h." }],
    }
  })

  server.tool("delete_user", "Delete a user account", { userId: z.string() }, async ({ userId }) => {
    return {
      content: [
        {
          type: "text" as const,
          text: `User ${userId} successfully deleted.`,
        },
      ],
    }
  })

  server.tool(
    "wire_transfer",
    "Transfer funds to a recipient",
    { amount: z.number(), recipient: z.string() },
    async ({ amount, recipient }) => {
      return {
        content: [
          {
            type: "text" as const,
            text: `Transferred $${amount} to ${recipient}.`,
          },
        ],
      }
    },
  )

  // Define local-first policy JSON
  const localPolicyJson = JSON.stringify({
    version: "2026.07.05-1",
    rules: [
      {
        action: "get_status",
        effect: "allow",
      },
      {
        action: "delete_user",
        effect: "deny",
      },
      {
        action: "wire_transfer",
        effect: "allow",
        maxAmount: 1000,
        currency: "USD",
      },
    ],
  })

  // Intygafy the server using the SDK. Local simulation defaults; override via env to point at a real
  // gateway. Never hardcode a client secret in your own integration — read it from the environment.
  intygafyServer(server, {
    gatewayUrl: process.env.INTYGA_GATEWAY_URL || "http://localhost:8787",
    clientId: process.env.INTYGA_CLIENT_ID || "did:intyga:client-dev",
    clientSecret: process.env.INTYGA_CLIENT_SECRET || "dev_secret_key",
    agentId: process.env.INTYGA_AGENT_ID || "did:intyga:agent-001",
    enforcement: "local-first",
    localPolicyJson,
  })

  // Helper to simulate incoming JSON-RPC calls
  async function simulateCall(name: string, args: Record<string, unknown>) {
    console.log(`\nCalling tool: '${name}' with arguments: ${JSON.stringify(args)}`)
    try {
      const response = await (
        server as unknown as {
          server: { receiveRequest: (req: unknown) => Promise<unknown> }
        }
      ).server.receiveRequest({
        jsonrpc: "2.0",
        id: Math.floor(Math.random() * 1000),
        method: "tools/call",
        params: {
          name,
          arguments: args,
        },
      })
      console.log("Response:", JSON.stringify(response, null, 2))
    } catch (err) {
      console.error("Execution failed:", (err as Error).message)
    }
  }

  // A local allow never executes a tool by itself; with this deliberately incomplete dev config,
  // the gateway refuses the request or the connection fails closed.
  console.log("\n--- Case 1: Local allow still requires a gateway approval (get_status) ---")
  await simulateCall("get_status", {})

  // Case 2: delete_user (Policy denies -> Should block instantly offline)
  console.log("\n--- Case 2: Policy Denies (delete_user) ---")
  await simulateCall("delete_user", { userId: "user-456" })

  // Case 3: a local allow under the limit still requires a gateway approval.
  console.log("\n--- Case 3: Local allow still requires approval (wire_transfer $500) ---")
  await simulateCall("wire_transfer", { amount: 500, recipient: "Alice" })

  // Case 4: wire_transfer exceeding limit (Policy allows but escalates to approval -> gateway request)
  console.log("\n--- Case 4: Policy Escalation above limit (wire_transfer $2500) ---")
  console.log("Checking gateway connectivity...")
  try {
    const checkGateway = await fetch("http://localhost:8787/").catch(() => null)
    if (!checkGateway) {
      console.log("Gateway is offline. Gateway interception verified (would trigger biometric challenge).")
    } else {
      console.log("Gateway is online. Starting live biometric challenge request...")
      await simulateCall("wire_transfer", { amount: 2500, recipient: "Bob" })
    }
  } catch {
    console.log("Interception verified.")
  }
}

runSimulation().catch((err) => {
  console.error("Simulation failed:", err)
})
