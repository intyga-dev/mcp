# Changelog

All notable changes to `@intyga/mcp-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- Package made publishable (`private` removed) with registry metadata and this changelog.

## [1.0.0]

- `intygafyServer(server, config)` — wraps both `server.tool` and `server.registerTool`, and
  re-gates `update({ callback })` replacements (including under a same-call rename).
- Fail-closed local policy evaluation (`evaluatePolicy`), Zod-validated at the boundary; shared
  with `@intyga/mcp-proxy` so both enforcement paths reach identical verdicts.
- `requestApproval` — challenge + poll to a terminal outcome against the Intyga gateway.
