# @intyga/mcp-sdk — gate an MCP server's tools behind a human approval

Middleware for [Model Context Protocol](https://modelcontextprotocol.io) servers: wrap your
`McpServer` once, and every tool it registers executes only after gateway authorization. For
AI-agent calls, the v1 receipt and RP execution check bind the human approval to the action.
A local policy can deny an action before the challenge is created. A prompt-injected
or credential-leaked agent can *request* a high-risk action — it cannot execute it alone.

For an `AI_AGENT` key, pass an RP-owned `agentV1` runtime. The wrapper sends v1 `agentContext`,
checks the complete receipt with `verifyAgentForExecution`, and requires an atomic nonce/session/
budget reservation before the tool handler runs. Without this runtime an agent request is refused
by the gateway. The RP must provide trusted live model/tool/prompt data and durable state; a model
cannot provide or attest these facts for itself.

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { intygafyServer } from "@intyga/mcp-sdk";
import agentV1 from "./rp-agent-v1.js"; // your trusted RP adapter; see contract below

const server = new McpServer({ name: "payments-tools", version: "1.0.0" });

intygafyServer(server, {
  gatewayUrl: process.env.INTYGA_GATEWAY_URL!,
  clientId: process.env.INTYGA_CLIENT_ID!,
  clientSecret: process.env.INTYGA_CLIENT_SECRET!,
  agentId: "did:intyga:agent-payments",
  // The relying party this server approves FOR (DIV Target Isolation). Defaults to agentId.
  target: "payments-prod",
  agentV1,
});

// Register tools as normal — every one of them is now gated.
server.tool("transfer_funds", /* schema */ {}, async (args) => {
  /* runs only after human approval and the v1 execution check */
  return { content: [{ type: "text", text: "done" }] };
});
```

## What the gate does, per tool call

1. **Local policy first** (`enforcement: "local-first"`): `deny` refuses immediately. `allow`
   proceeds to the approval path; it never executes the tool by itself. This also holds when an
   AI-agent key was configured without `agentV1`, so forgetting the runtime cannot bypass v1.
2. **Everything else goes through the gateway.** The gateway raises a challenge or applies its
   configured approval policy. For `AI_AGENT`, the wrapper
   verifies the receipt and reserves the session before calling the tool. Default wait is 120 s,
   polling every 2 s (`timeoutMs` / `intervalMs` to override).
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
- `effect` is one of `allow` | `deny` | `require_approval`. In this adapter, both `allow` and
  `require_approval` require a gateway challenge; only `deny` resolves locally.
- The manifest is Zod-validated at the boundary. Shapes like `{"rules": 5}` or a rule with
  `maxAmount: "abc"` do not throw and do not allow — they escalate.

## v1 agent runtime contract

`agentV1` implements the exported `AgentV1Runtime` interface:

- `requesterDid`, `approvers`, `verifier`: pin the registered agent DID, approver keys and WebAuthn
  origin/RP ID from RP-controlled configuration. A delegated agent also needs the trusted complete
  authority chain in `verifier.agentAuthorityChain`.
- `prepare(actionType, params)`: derive `action.reversibility`, decimal `action.amount`,
  `delegatedBy` and `{ id, seq, prev, aggregate }` from RP-owned records. The wrapper computes
  `configDigest` from `liveConfig()` and sends the input to `/authorize`.
- `liveConfig()`: read the actual model version, tool identities/schema digests and system prompt
  from the runtime at request time **and again immediately before execution**. A digest is an RP
  assertion, not proof of agent integrity without this check.
- `readState(sessionId)`: read the durable head, sequence and aggregate at execution time.
- `reserve({ nonce, sessionId, prior, next, amount })`: in one durable transaction, reject a
  previously used nonce, compare the current state with `prior`, enforce the cross-session budget,
  then store `next` and the nonce. Return `false` on conflict. A process-local map is insufficient.

These hooks are intentionally supplied by the executing RP: the wrapper cannot know its database,
trusted approver enrollment or live agent runtime. The receipt is consumed at the gateway before
local verification/reservation; a local refusal burns it and never runs the tool. A crash after
reservation can leave an approved action unexecuted, but cannot authorize a second execution.
Do not put raw prompts or personal data in receipt fields or logs.

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
  `{ outcome: "approved", nonce }` only after v1 verification/reservation when `agentV1` is present,
  `{ outcome: "refused", status, reason }`, or
  `{ outcome: "error", reason }`.

`IntygaConfig`: `gatewayUrl`, `clientId`, `clientSecret`, `agentId`, `target?` (defaults to
`agentId`), `enforcement?` (`"local-first"` default | `"gateway-enforced"`), `localPolicyJson?`,
`timeoutMs?`, `intervalMs?`, `agentV1?` (required with an AI_AGENT key).

## Related

- [`@intyga/mcp-proxy`](../mcp-proxy) — the same gate as a stdio proxy, for servers you don't own.
- Connecting an agent straight to the gateway's hosted MCP endpoint (no server-side install):
  see the repo root README.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
