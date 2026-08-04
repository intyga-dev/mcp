# @intyga/mcp-sdk — gate an MCP server's tools behind a human approval

Middleware for [Model Context Protocol](https://modelcontextprotocol.io) servers: wrap your
`McpServer` once, and every tool it registers executes only after a local policy allows it or a
human approves it with a passkey / hardware security key via your Intyga gateway. A prompt-injected
or credential-leaked agent can *request* a high-risk action — it cannot execute it alone.

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { intygafyServer } from "@intyga/mcp-sdk";

const server = new McpServer({ name: "payments-tools", version: "1.0.0" });

intygafyServer(server, {
  gatewayUrl: process.env.INTYGA_GATEWAY_URL!,
  clientId: process.env.INTYGA_CLIENT_ID!,
  clientSecret: process.env.INTYGA_CLIENT_SECRET!,
  agentId: "did:intyga:agent-payments",
  // The relying party this server approves FOR (DIV Target Isolation). Defaults to agentId.
  target: "payments-prod",
});

// Register tools as normal — every one of them is now gated.
server.tool("transfer_funds", /* schema */ {}, async (args) => {
  /* runs only after policy-allow or human approval */
  return { content: [{ type: "text", text: "done" }] };
});
```

## What the gate does, per tool call

1. **Local policy first** (`enforcement: "local-first"`): the call is checked against your policy
   manifest. `allow` executes immediately; `deny` refuses immediately.
2. **Everything else escalates to a human.** The gateway raises a challenge; the registered
   approver signs (or declines) with their passkey / security key; the tool runs only on
   `APPROVED`. Default wait is 120 s, polling every 2 s (`timeoutMs` / `intervalMs` to override).
3. **Fail closed.** Absent policy, unparseable policy, an unknown action, a malformed rule, or
   `enforcement: "gateway-enforced"` — all of these escalate rather than execute. One malformed
   rule fails the whole policy document on purpose: a policy the operator cannot have meant is not
   a policy to partially honour.

## Local policy manifest

Passed as a JSON string via `localPolicyJson`:

```json
{
  "rules": [
    { "action": "get_balance", "effect": "allow" },
    { "action": "transfer_funds", "maxAmount": 1000, "effect": "allow" },
    { "action": "close_account", "effect": "deny" }
  ]
}
```

- `action` matches the tool name; an unmatched tool escalates to approval.
- `maxAmount` is a ceiling on the call's `amount`/`value` parameter — above it (or when the
  amount is not a real number) the rule does not apply and the call escalates.
- `effect` is one of `allow` | `deny` | `require_approval`.
- The manifest is Zod-validated at the boundary. Shapes like `{"rules": 5}` or a rule with
  `maxAmount: "abc"` do not throw and do not allow — they escalate.

## Coverage — worth knowing exactly

Both registration entrypoints are wrapped: `server.tool(...)` **and** `server.registerTool(...)`
(they are separate code paths in `@modelcontextprotocol/sdk`, and current MCP docs steer users to
the latter). The handle returned by registration is patched too, so
`registered.update({ callback })` re-gates the replacement handler — including under a rename in
the same call, which changes which policy rule applies.

Not covered, stated plainly: a caller that bypasses `McpServer` entirely and installs a raw
`tools/call` handler on the underlying low-level `Server`. If you need that gated with no code
changes to the server, put [`@intyga/mcp-proxy`](../mcp-proxy) in front of it instead.

## API

- `intygafyServer(server, config)` — wrap every tool registration on an `McpServer`.
- `evaluatePolicy(actionName, args, ctx)` — the pure local-policy gate (`"allow" | "deny" |
  "require_approval"`). Shared with `@intyga/mcp-proxy` so the two enforcement paths cannot reach
  different verdicts for the same call.
- `requestApproval(request)` — raise a challenge and poll it to a terminal state; resolves to
  `{ outcome: "approved", nonce }`, `{ outcome: "refused", status, reason }`, or
  `{ outcome: "error", reason }`.

`IntygaConfig`: `gatewayUrl`, `clientId`, `clientSecret`, `agentId`, `target?` (defaults to
`agentId`), `enforcement?` (`"local-first"` default | `"gateway-enforced"`), `localPolicyJson?`,
`timeoutMs?`, `intervalMs?`.

## Related

- [`@intyga/mcp-proxy`](../mcp-proxy) — the same gate as a stdio proxy, for servers you don't own.
- Connecting an agent straight to the gateway's hosted MCP endpoint (no server-side install):
  see the repo root README.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
