import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { sakrafyServer } from "./index.js"

const server = new McpServer({
  name: "sakra-secured-server",
  version: "1.0.0",
})

// 1. APPLY MIDDLEWARE FIRST
// This ensures every future call to server.tool is captured.
// Credentials come from the environment — never hardcode a client secret. Get these from the SÄKRA
// console (My Agents → create agent → mint agent key); the fallbacks below are local-dev placeholders.
sakrafyServer(server, {
  gatewayUrl: process.env.SAKRA_GATEWAY_URL || "http://localhost:8787",
  clientId: process.env.SAKRA_CLIENT_ID || "did:sakra:human-owner",
  clientSecret: process.env.SAKRA_CLIENT_SECRET || "dev_secret_key",
  agentId: process.env.SAKRA_AGENT_ID || "did:sakra:agent-001",
  enforcement: "local-first",
  localPolicyJson: JSON.stringify({
    version: "2026.07.05-1",
    rules: [
      { action: "get_status", effect: "allow" },
      { action: "delete_user", effect: "deny" },
      {
        action: "wire_transfer",
        effect: "allow",
        maxAmount: 1000,
        currency: "USD",
      },
    ],
  }),
})

// 2. NOW REGISTER TOOLS
// These will now automatically be wrapped by your secureHandler
server.tool("get_status", "Get server status", {}, async () => {
  console.error("[SÄKRA] Executing get_status...")
  return { content: [{ type: "text", text: "System normal. Up 24h." }] }
})

server.tool("delete_user", "Delete a user account", { userId: z.string() }, async ({ userId }) => {
  console.error(`[SÄKRA] Executing delete_user for ${userId}...`)
  return { content: [{ type: "text", text: `User ${userId} deleted.` }] }
})

server.tool(
  "wire_transfer",
  "Transfer funds",
  { amount: z.number(), recipient: z.string() },
  async ({ amount, recipient }) => {
    console.error(`[SÄKRA] Executing wire_transfer of ${amount} to ${recipient}...`)
    return {
      content: [{ type: "text", text: `Transferred $${amount} to ${recipient}.` }],
    }
  },
)

// 3. START SERVER
const transport = new StdioServerTransport()
await server.connect(transport)
console.error("SÄKRA Secured MCP Server running on stdio")
