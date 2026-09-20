# Changelog

All notable changes to `@intyga/mcp-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- AI-agent keys now use the single v1 receipt flow: RP-owned `AgentV1Runtime` supplies the context,
  live configuration, trusted approvers and durable reservation; the wrapper verifies the receipt
  before calling a handler. A local `allow` rule can no longer execute a tool on its own.
- Snapshot MCP JSON arguments before approval so the handler receives the values that were signed.
- `requestApproval` re-exchanges the client credentials once when a status check answers 401
  mid-wait (the agent token outlived its TTL — a `timeoutMs` longer than the token's life does
  this) and redeems the approval with the new token, instead of counting the 401s as polling
  failures and aborting the wait. A second 401 after that is an ordinary failure.
- Package made publishable (`private` removed) with registry metadata and this changelog.

## [1.0.0]

- `intygafyServer(server, config)` — wraps both `server.tool` and `server.registerTool`, and
  re-gates `update({ callback })` replacements (including under a same-call rename).
- Fail-closed local policy evaluation (`evaluatePolicy`), Zod-validated at the boundary; shared
  with `@intyga/mcp-proxy` so both enforcement paths reach identical verdicts.
- `requestApproval` — challenge + poll to a terminal outcome against the Intyga gateway.
