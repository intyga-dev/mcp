# @intyga/mcp-sdk — gate an MCP server's tools behind a human approval

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

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
   verifies the receipt, consumes it once, and reserves the session before calling the tool. SERVICE
   and human credentials require equivalent independent checks through `executionTrust`. Default wait is 120 s,
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

## Required execution trust

Every integration supplies RP-owned `tenantId`, `requesterDid`, `approvers`, and `requirement`.
For SERVICE/human credentials provide them as `executionTrust`; for AI_AGENT credentials they are
part of `agentV1`. Neither gateway status nor keys embedded in a receipt are trusted. Receipts are
verified before one-time consumption, and `AUTO_APPROVED` receipts are always refused.

## v1 agent runtime contract

`agentV1` implements the exported `AgentV1Runtime` interface:

- `tenantId`, `requesterDid`, `approvers`, `requirement`, `verifier`: pin the tenant, registered agent DID,
  approver keys, ordinary rule floor and WebAuthn
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
trusted approver enrollment or live agent runtime. The receipt is locally verified before gateway
consumption. Consumption precedes reservation, so a reservation conflict may safely burn an approval
but never runs the tool. A crash after
reservation can leave an approved action unexecuted, but cannot authorize a second execution.
Do not put raw prompts or personal data in receipt fields or logs.

## Coverage — worth knowing exactly

The adapter pins `@modelcontextprotocol/sdk` 1.32.1, requires an exact instance of that pinned
`McpServer` class (not a subclass or another installed copy), and intercepts its common registered-
tool creation primitive. This covers `tool`, `registerTool`, `experimental.tasks.registerToolTask`,
tools registered before wrapping, callback replacement, and rename-only updates. An unknown SDK
shape is refused during setup rather than left callable without approval.
Parsed arguments are snapshotted before the first await. Caller `_meta` is removed before the
business callback except for the transport-only `progressToken`; task routing stays in the MCP
context's dedicated task fields.

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
- `assertExecutionTrust(value)` — validate an RP-owned tenant/requester/approver/floor module at
  startup; used by the proxy loader and available to custom launchers.

The executable requirement floor supports `requiredApprovals`, `requesterCannotApprove`,
`requireHardwareKey`, and `excludedSignerDids`. Other receipt-policy fields, including `allowedAaguids` and `signerClass`, are
rejected during setup rather than silently ignored. Use `requireHardwareKey` when direct model
restrictions are needed; its offline assurance limits remain those documented by the verifier.

`IntygaConfig`: `gatewayUrl`, `clientId`, `clientSecret`, `agentId`, `target?` (defaults to
`agentId`), `enforcement?` (`"local-first"` default | `"gateway-enforced"`), `localPolicyJson?`,
`timeoutMs?`, `intervalMs?`, and exactly one of `agentV1` (AI_AGENT) or `executionTrust`
(SERVICE/human).

`gatewayUrl` must be `https://`: `intygafyServer` throws (and `requestApproval` returns an `error`
outcome) for plain `http://` except to a loopback host (`localhost`, `127.0.0.0/8`, `::1`), and no
gateway request follows a redirect.

## Related

- [`@intyga/mcp-proxy`](../mcp-proxy) — the same gate as a stdio proxy, for servers you don't own.
- Connecting an agent straight to the gateway's hosted MCP endpoint (no server-side install):
  see the repo root README.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).

### TypeScript library types

The upstream `@modelcontextprotocol/sdk` exposes `HeadersInit` in its transport declarations. Include
`"DOM"` alongside your ECMAScript library in `tsconfig.json` (for example,
`"lib": ["ES2022", "DOM"]`), including for Node-only consumers of this wrapper.
