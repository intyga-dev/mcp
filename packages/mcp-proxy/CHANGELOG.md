# Changelog

All notable changes to `@intyga/mcp-proxy` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- `--agent-v1-module` loads an RP-owned runtime for v1 AI-agent context, receipt verification and
  atomic nonce/session/budget reservation. Local `allow` never forwards a tool without approval.
- Package made publishable (`private` removed) with registry metadata and this changelog.

## [1.0.0]

- Stdio proxy gating a third-party MCP server's `tools/call` traffic behind local policy +
  human approval, with no changes to the wrapped server.
- Fail-closed handling of non-JSON lines and JSON-RPC batches; canonical re-serialization of
  forwarded messages; FIFO serialization of gated calls; `INTYGA_*` stripped from the child
  environment; `--target-args` object smuggling refused.
