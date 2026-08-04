# @intyga/mcp-proxy — human approval in front of any MCP server, no code changes

A stdio proxy that sits between an MCP client (the agent) and a third-party MCP server. Every
`tools/call` is checked against your local policy and, when the policy does not explicitly allow
it, held until a human approves it with a passkey / hardware security key via your Intyga gateway.
The wrapped server is not modified and is deliberately not trusted.

```sh
intyga-proxy \
  --target-command npx \
  --target-args '["-y", "@modelcontextprotocol/server-filesystem", "/data"]' \
  --agent-id did:intyga:agent-fs \
  --target fileserver-prod \
  --local-policy ./policy.json
```

Point your MCP client's stdio server config at `intyga-proxy` instead of the real server; the
proxy spawns the real server as a child and mediates the protocol stream.

## Flags and environment

| Flag | Env var | Meaning |
| :--- | :--- | :--- |
| `--gateway-url` | `INTYGA_GATEWAY_URL` | Intyga gateway (default `http://localhost:8787`) |
| `--client-id` | `INTYGA_CLIENT_ID` | Agent credential id |
| `--client-secret` | `INTYGA_CLIENT_SECRET` | **Use the env var.** The flag is accepted but warns: argv is world-readable via `ps`, including by the wrapped server — the one process this proxy exists to distrust |
| `--agent-id` | `INTYGA_AGENT_ID` | The agent identity raising approvals |
| `--target` | `INTYGA_TARGET` | Relying-party identifier approvals are bound to (DIV Target Isolation). Defaults to the agent id — never to the gateway's `"global"` fallback |
| `--enforcement` | — | `local-first` (default) or `gateway-enforced` (every call escalates) |
| `--local-policy` | — | Path to a policy manifest JSON — same format and same evaluator as [`@intyga/mcp-sdk`](../mcp-sdk), so the two enforcement paths cannot disagree |
| `--target-command` | — | The real MCP server executable (required) |
| `--target-args` | — | Its arguments, as a JSON **array of strings** — an object is refused, because Node would read it as the spawn *options* and a `{"shell": true}` smuggle would turn the command into a shell string |

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
  target server whose parser resolves duplicates differently.
- **Gated calls run one at a time, FIFO.** Two mutating calls cannot be reordered around each
  other, and a runaway agent cannot fan out unbounded approval prompts. Non-mutating protocol
  traffic (`initialize`, `ping`, `*/list`) bypasses the queue so a pending human decision cannot
  make the client conclude the server is dead.
- **The wrapped server never sees your Intyga credentials.** Every `INTYGA_*` variable is stripped
  from the child's environment; everything else passes through.

## Runtime

The binary is TypeScript executed directly: **Node ≥ 24** (type stripping is on by default).
On older Node, run it via `tsx src/cli.ts …`.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
