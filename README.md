# Intyga for MCP — Human Approval for AI Agent Tool Calls

Client-side tooling that gates an AI agent's [Model Context Protocol](https://modelcontextprotocol.io)
tool calls behind a cryptographically-signed human approval. A leaked credential or a prompt-injected
agent can *request* a high-risk action — it can never execute it alone.

**MFA verifies who you are. Intyga verifies what you are doing.**

These packages run on your side and call your Intyga gateway to broker the approval; Intyga witnesses
the sign-off without ever holding your keys or executing your tools. The gateway, the tamper-evident
witness ledger, and server-side policy enforcement are hosted by Intyga.

---

## Packages

| Package | Purpose |
| :--- | :--- |
| `@intyga/mcp-sdk` | Middleware that wraps an existing MCP server so every `server.tool` call is gated. |
| `@intyga/mcp-proxy` | A stdio proxy that enforces policy in front of an MCP server, no code changes. |

---

## Two ways to integrate

**1. Connect to the hosted approval endpoint (lowest friction, nothing to install).**
Point your agent at the Intyga gateway's MCP endpoint over SSE with a Bearer agent token — add it to
your client's `mcp.json`:

```json
{
  "mcpServers": {
    "intyga": {
      "type": "sse",
      "url": "https://api.intyga.com/mcp/sse",
      "headers": { "Authorization": "Bearer <your_agent_token>" }
    }
  }
}
```

The endpoint provides two tools:

* **`verify_human_authorization`** — initiates a challenge; returns a `nonce` and `PENDING` while a
  request goes to the registered human approver's passkey/device.
* **`check_human_authorization`** — polls by `nonce`; returns `PENDING`, `APPROVED` (with the
  cryptographic signature receipt), `DENIED`, or `EXPIRED`.

The agent requests sign-off, polls until it resolves, then executes its own action.

**2. Wrap your existing MCP server (transparent gating).**
Use `@intyga/mcp-sdk` to gate the tools you already expose, without teaching the agent to call an
approval tool explicitly:

```bash
npm install @intyga/mcp-sdk
```

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { intygafyServer } from "@intyga/mcp-sdk";
import { z } from "zod";

const server = new McpServer({ name: "my-secured-server", version: "1.0.0" });

// Apply the middleware BEFORE registering tools so every server.tool call is captured.
// Credentials come from the environment — never hardcode a client secret.
intygafyServer(server, {
  gatewayUrl: process.env.INTYGA_GATEWAY_URL!,
  clientId: process.env.INTYGA_CLIENT_ID!,
  clientSecret: process.env.INTYGA_CLIENT_SECRET!,
  agentId: process.env.INTYGA_AGENT_ID!,
  enforcement: "local-first",
});

// Registered after intygafyServer — now gated automatically.
server.tool("wire_transfer", "Transfer funds", { amount: z.number() }, async ({ amount }) => {
  /* only runs once a human has signed off */
});
```

The local policy is **advisory** — it can only make governance *stricter*. Whether a human must
sign, the quorum, and any hardware-key / four-eyes constraints are decided server-side by your
organization's Approval Rules, which the agent cannot see or weaken.

---

## License

Apache-2.0. These are the open, inspectable client components — read them before you put them in
your agent's tool-call path. See each package's `LICENSE`.
