# Changelog

All notable changes to `@intyga/mcp-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [3.1.1]

- Update the runtime `@modelcontextprotocol/sdk` pin to 1.32.2. Consumers that pass an
  `McpServer` to the wrapper must use the same MCP SDK version to avoid incompatible private
  class types. The approval and verification behavior is unchanged.

## [3.1.0]

- `executionTrust` and `agentV1` accept an optional RP-owned `enrolledDeviceKeys` (DIV §4.3.2,
  ADR 027), passed to receipt verification, and the requirement floor admits
  `requireEnrolledDevice`. Without the keys a receipt whose signed policy requires an enrolled
  approver device is refused, as before.

## [3.0.0]

- **Breaking:** require RP-owned tenant, requester, approver trust, and requirement floor for every
  execution (`agentV1` or `executionTrust`); verify before consume and refuse `AUTO_APPROVED`.
- Pin MCP SDK 1.32.1 and gate its common registration primitive, including pre-registered, task,
  replacement, and renamed tools. Unsupported runtime shapes fail closed during setup.
- Snapshot parsed arguments, strip caller `_meta` except `progressToken`, and re-check receipt time
  and live agent configuration synchronously after consume/reservation immediately before execution.
- Reject unsupported requirement-floor fields and malformed self-certifying approver DIDs during
  setup instead of accepting policy that the executable verifier cannot enforce.
- `ApprovalRequest.signal` now cancels token exchange, challenge creation, polling sleep/status,
  redemption, and final execution checks so a shutting-down relying party cannot consume or execute
  a previously queued approval.

## [2.1.0]

- `IntygaConfig.reportDispatch: { evidenceWithinSeconds }` reports the dispatch of an approved tool
  call after it runs (DEWP 1.1 §4.7 execution evidence), best effort and even when the handler throws.
  New export `reportDispatched`.

## [2.0.0]

- **Breaking dependency upgrade:** use `@intyga/sdk` 2.x for tenant-bound DIV v2 approvals.
  Existing installations must upgrade before the gateway v2 cutover. The wrapper continues to
  require human approval for every allowed tool call.

## [1.0.0]

- **Security (L21, I11):** the approval client never follows a redirect (a followed 307 re-sent
  the token request and the approval request to another origin); every gateway request uses
  `redirect: "manual"` and a 30 s timeout, a 3xx is reported as an error, and a redirect on the
  status poll ends the wait at once. `intygafyServer` throws, and `requestApproval` returns an
  `error` outcome, for a non-`https://` `gatewayUrl` other than a loopback host. Re-exports
  `assertGatewayUrl`.

- Packaging: source maps are off in the published build. This package ships `dist` only, so the maps
  pointed at `../src/*.ts` files that are not in the tarball. `@intyga/sdk` is declared as
  `workspace:^` so a packed release pins `^1.0.0` rather than the exact version.
- AI-agent keys now use the single v1 receipt flow: RP-owned `AgentV1Runtime` supplies the context,
  live configuration, trusted approvers and durable reservation; the wrapper verifies the receipt
  before calling a handler. A local `allow` rule can no longer execute a tool on its own.
- Snapshot MCP JSON arguments before approval so the handler receives the values that were signed.
- `requestApproval` re-exchanges the client credentials once when a status check answers 401
  mid-wait (the agent token outlived its TTL — a `timeoutMs` longer than the token's life does
  this) and redeems the approval with the new token, instead of counting the 401s as polling
  failures and aborting the wait. A second 401 after that is an ordinary failure.
- Package made publishable (`private` removed) with registry metadata and this changelog.


- `intygafyServer(server, config)` — wraps both `server.tool` and `server.registerTool`, and
  re-gates `update({ callback })` replacements (including under a same-call rename).
- Fail-closed local policy evaluation (`evaluatePolicy`), Zod-validated at the boundary; shared
  with `@intyga/mcp-proxy` so both enforcement paths reach identical verdicts.
- `requestApproval` — challenge + poll to a terminal outcome against the INTYGA gateway.
