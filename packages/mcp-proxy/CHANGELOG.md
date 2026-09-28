# Changelog

All notable changes to `@intyga/mcp-proxy` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Security (I11):** a non-`https://` `--gateway-url` / `INTYGA_GATEWAY_URL` is refused at startup,
  before the target server is spawned, except loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
  Gateway requests no longer follow redirects (via `@intyga/mcp-sdk`).

- **Security: a `tools/call` whose `arguments` was not a JSON object was approved as `{}` and then
  forwarded as sent.** The human saw "drop_database with {}" while the target received
  `["production"]`. Such calls (and a non-string `name`) are now refused with JSON-RPC `-32602`
  before any approval is requested, and an approved call is forwarded rebuilt from exactly the
  approved `name` + `arguments` (keeping only `_meta.progressToken`), never from the client's message.
- **The published package now ships a compiled `dist/cli.js`, and `bin` points at it.** It previously
  shipped `src/cli.ts` and relied on Node 24 type stripping, which cannot work from an install: Node
  refuses to strip types for any file under `node_modules`
  (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`), so the only entry point failed on first run at
  every Node version. Reproduced from a packed install and fixed; the build excludes tests via
  `tsconfig.build.json` while `tsc --noEmit` still typechecks them. No behaviour change — the
  policy, enforcement and fail-closed paths are byte-identical source.
- `@intyga/mcp-sdk` is declared as `workspace:^`, so a packed release pins `^1.0.0` rather than the
  exact version `workspace:*` produced.
- `--agent-v1-module` loads an RP-owned runtime for v1 AI-agent context, receipt verification and
  atomic nonce/session/budget reservation. Local `allow` never forwards a tool without approval.
- Package made publishable (`private` removed) with registry metadata and this changelog.

## [1.0.0]

- Stdio proxy gating a third-party MCP server's `tools/call` traffic behind local policy +
  human approval, with no changes to the wrapped server.
- Fail-closed handling of non-JSON lines and JSON-RPC batches; canonical re-serialization of
  forwarded messages; FIFO serialization of gated calls; `INTYGA_*` stripped from the child
  environment; `--target-args` object smuggling refused.
