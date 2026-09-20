import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import fs from "node:fs"
import { pathToFileURL } from "node:url"
import { z } from "zod"
import { intygafyServer, type AgentV1Runtime } from "./index.js"

const server = new McpServer({
  name: "intyga-secured-server",
  version: "1.0.0",
})

// 1. APPLY MIDDLEWARE FIRST
// This ensures every future call to server.tool is captured.
// This runnable example uses an AI_AGENT key. The RP-owned v1 module must provide live configuration,
// trusted approvers and a durable nonce/session/budget reservation. It cannot be supplied by the model.
const modulePath = process.env.INTYGA_AGENT_V1_MODULE
if (!modulePath) throw new Error("INTYGA_AGENT_V1_MODULE is required for an AI_AGENT tool server")
const agentV1 = (await import(pathToFileURL(fs.realpathSync(modulePath)).href)).default as AgentV1Runtime
if (
  !agentV1?.requesterDid ||
  !agentV1.prepare ||
  !agentV1.liveConfig ||
  !agentV1.readState ||
  !agentV1.reserve
)
  throw new Error("INTYGA_AGENT_V1_MODULE must export an RP-owned AgentV1Runtime")
if (!process.env.INTYGA_CLIENT_ID || !process.env.INTYGA_CLIENT_SECRET)
  throw new Error("INTYGA_CLIENT_ID and INTYGA_CLIENT_SECRET are required")
intygafyServer(server, {
  gatewayUrl: process.env.INTYGA_GATEWAY_URL || "http://localhost:8787",
  clientId: process.env.INTYGA_CLIENT_ID,
  clientSecret: process.env.INTYGA_CLIENT_SECRET,
  agentId: process.env.INTYGA_AGENT_ID || agentV1.requesterDid,
  agentV1,
  enforcement: "local-first",
  localPolicyJson: JSON.stringify({
    version: "2026.07.05-1",
    rules: [
      { action: "get_status", effect: "allow" }, // still requires a signed approval
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
  console.error("[Intyga] Executing get_status...")
  return { content: [{ type: "text", text: "System normal. Up 24h." }] }
})

server.tool("delete_user", "Delete a user account", { userId: z.string() }, async ({ userId }) => {
  console.error(`[Intyga] Executing delete_user for ${userId}...`)
  return { content: [{ type: "text", text: `User ${userId} deleted.` }] }
})

server.tool(
  "wire_transfer",
  "Transfer funds",
  { amount: z.number(), recipient: z.string() },
  async ({ amount, recipient }) => {
    console.error(`[Intyga] Executing wire_transfer of ${amount} to ${recipient}...`)
    return {
      content: [{ type: "text", text: `Transferred $${amount} to ${recipient}.` }],
    }
  },
)

// 3. START SERVER
const transport = new StdioServerTransport()
await server.connect(transport)
console.error("Intyga Secured MCP Server running on stdio")
