# @intyga/mcp-proxy — human approval in front of any MCP server, no code changes

A stdio proxy that sits between an MCP client (the agent) and a third-party MCP server. Every
`tools/call` is checked against your local policy; a `deny` is refused locally and every other
result goes through your INTYGA gateway's authorization flow. AI-agent execution also requires a
v1 receipt and RP check of the human approval.
The wrapped server is not modified and is deliberately not trusted.

For an `AI_AGENT` key, pass `--agent-v1-module` pointing to an RP-owned JavaScript module whose
default export implements `AgentV1Runtime` from `@intyga/mcp-sdk`. The proxy then sends the v1
`agentContext`, verifies the complete receipt against RP-pinned approvers and live configuration,
and requires an atomic nonce/session/budget reservation before forwarding the call. Without that
module the gateway refuses AI-agent requests.

```sh
intyga-proxy \
  --target-command npx \
  --target-args '["-y", "@modelcontextprotocol/server-filesystem", "/data"]' \
  --agent-id did:intyga:agent-fs \
  --target fileserver-prod \
  --agent-v1-module ./rp-agent-v1.mjs \
  --local-policy ./policy.json
```

Point your MCP client's stdio server config at `intyga-proxy` instead of the real server; the
proxy spawns the real server as a child and mediates the protocol stream.

## Flags and environment

| Flag | Env var | Meaning |
| :--- | :--- | :--- |
| `--gateway-url` | `INTYGA_GATEWAY_URL` | INTYGA gateway (default `http://localhost:8787`). Must be `https://`; plain `http://` is refused at startup except to a loopback host (`localhost`, `127.0.0.0/8`, `::1`) |
| `--client-id` | `INTYGA_CLIENT_ID` | Agent credential id |
| `--client-secret` | `INTYGA_CLIENT_SECRET` | **Use the env var.** The flag is accepted but warns: argv is world-readable via `ps`, including by the wrapped server — the one process this proxy exists to distrust |
| `--agent-id` | `INTYGA_AGENT_ID` | Default value for `--target` when that is unset. Never sent to the gateway — the identity the ledger records as requester comes from the `--client-id` credential exchange |
| `--target` | `INTYGA_TARGET` | Relying-party identifier approvals are bound to (DIV Target Isolation). Defaults to the agent id — never to the gateway's `"global"` fallback |
| `--enforcement` | — | `local-first` (default) or `gateway-enforced` (every call escalates) |
| `--local-policy` | — | Path to a policy manifest JSON — same format and same evaluator as [`@intyga/mcp-sdk`](../mcp-sdk), so the two enforcement paths cannot disagree |
| `--target-command` | — | The real MCP server executable (required) |
| `--target-args` | — | Its arguments, as a JSON **array of strings** — an object is refused, because Node would read it as the spawn *options* and a `{"shell": true}` smuggle would turn the command into a shell string |
| `--agent-v1-module` | `INTYGA_AGENT_V1_MODULE` | Absolute or relative path to the trusted RP v1 runtime module. Mandatory for AI-agent keys. Export `default` with `requesterDid`, `approvers`, `verifier`, `prepare`, `liveConfig`, `readState`, and `reserve` as documented in [`@intyga/mcp-sdk`](../mcp-sdk). |

## Security properties (each of these is tested)

- **Fail closed, everywhere.** A line that is not valid JSON is refused with a JSON-RPC `-32700`,
  never forwarded — lenient parsers on the far side (Python's `json.loads` accepts `NaN`) can read
  a "non-JSON" line as a tool call this proxy never saw. A throw anywhere in the gate refuses the
  call; it never falls back to forwarding.
- **JSON-RPC batches are refused** (`-32600`). A batch has no top-level `method`, so it would
  classify as non-tool traffic while carrying any number of ungated `tools/call` entries. MCP
  removed batching in revision 2025-06-18; one request per line.
- **The approved bytes are the executed bytes.** Messages are re-serialized from the parse this
  proxy evaluated, so a duplicate-key payload cannot read as `ping` here and as a tool call to a
  target server whose parser resolves duplicates differently. An approved `tools/call` is rebuilt
  from exactly the approved `name` and `arguments` (plus `_meta.progressToken`, which only
  correlates progress notifications); any other `_meta` key, `params` field (including MCP task
  augmentation) or top-level member is dropped. A `tools/call` whose `name` is not a string, or
  whose `arguments` is present but not a JSON object, is refused with `-32602` before any approval
  is requested. Omitted `arguments` becomes `{}` for both approval and execution.
- **Gated calls run one at a time, FIFO.** Two mutating calls cannot be reordered around each
  other, and a runaway agent cannot fan out unbounded approval prompts. Non-mutating protocol
  traffic (`initialize`, `ping`, `*/list`) bypasses the queue so a pending human decision cannot
  make the client conclude the server is dead.
- **v1 agent calls require a receipt and an RP reservation.** Even a local `allow` rule cannot skip
  that check, including when `--agent-v1-module` was omitted. The gateway refuses an AI-agent key
  without its v1 context. `reserve` must use a durable compare-and-swap
  transaction and enforce the budget across sessions. The proxy does not provide a database or a
  trustworthy view of the agent's actual model, tools or prompt; your RP module must provide both.
- **The wrapped server never sees your INTYGA credentials.** Every `INTYGA_*` variable is stripped
  from the child's environment; everything else passes through. Run untrusted third-party servers
  under a separate OS identity or sandbox so they cannot read the RP module's state, files or parent
  process. Environment filtering alone is not an OS security boundary.

## Runtime

The published package ships compiled JavaScript (`dist/cli.js`); `npx @intyga/mcp-proxy` and a
global install both run it with no toolchain of their own. **Node ≥ 24.**

It used to ship the TypeScript entry point directly and rely on Node’s type stripping. That cannot
work from an installed package: Node refuses to strip types for any file under `node_modules`
(`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), at every version, so the only entry point failed on
first run. Working from a clone is unaffected — `tsx src/cli.ts …` still runs the source.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
