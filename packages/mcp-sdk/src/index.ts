import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { requestApproval } from "./approval-client.js"
import { evaluatePolicy } from "./policy.js"

export { requestApproval } from "./approval-client.js"
export type { ApprovalOutcome, ApprovalRequest } from "./approval-client.js"
export { evaluatePolicy } from "./policy.js"
export type { PolicyContext, PolicyDecision, PolicyManifest, PolicyRule } from "./policy.js"

export interface IntygaConfig {
  gatewayUrl: string
  clientId: string
  clientSecret: string
  agentId: string
  /**
   * This server's relying-party / execution-environment identifier, bound into every signed intent
   * (DIV §3 Invariant 5, Target Isolation). Defaults to `agentId`, which is the identity this
   * process already asserts — never to `"global"`, which is what the gateway falls back to when the
   * field is absent and which binds no environment at all.
   */
  target?: string
  enforcement?: "local-first" | "gateway-enforced"
  localPolicyJson?: string
  /**
   * Approval-poll overrides, forwarded to `requestApproval`. Leave unset in production: the
   * defaults (120s window, 2s poll) are sized for a human reaching for a device, not for tests.
   */
  timeoutMs?: number
  intervalMs?: number
}

type ToolHandler = (handlerArgs: Record<string, unknown>, extra: unknown) => Promise<unknown>

/**
 * Put every tool this server registers behind the Intyga gate.
 *
 * Both registration entrypoints are wrapped, not just one. `server.tool` is marked `@deprecated` in
 * @modelcontextprotocol/sdk and `registerTool` is a separate code path that never routes through it —
 * so wrapping only `tool` meant a consumer following current MCP docs got a server with no gate at
 * all, silently and with no warning. `RegisteredTool.update({ callback })` is wrapped for the same
 * reason: it replaces the handler after registration, discarding whatever the wrapper installed.
 *
 * Not covered, and out of reach from here: a caller who bypasses `McpServer` entirely and installs a
 * `tools/call` handler on the underlying low-level `Server`. Gating that would mean intercepting the
 * request handler rather than registration, which is the more robust design if this keeps moving.
 */
export function intygafyServer(server: McpServer, config: IntygaConfig) {
  const gate =
    (name: string, originalHandler: ToolHandler): ToolHandler =>
    async (handlerArgs: Record<string, unknown>, extra: unknown): Promise<unknown> => {
      // 1. Evaluate policy (local-first check)
      const decision = evaluatePolicy(name, handlerArgs, config)

      // If the policy allows, execute the tool immediately
      if (decision === "allow") {
        return originalHandler(handlerArgs, extra)
      }

      // If the policy denies, block the action immediately
      if (decision === "deny") {
        return {
          content: [
            {
              type: "text",
              text: `Security Violation: Action '${name}' is denied by Intyga policy.`,
            },
          ],
        }
      }

      // Otherwise, request human approval (biometric step-up) via Intyga Gateway API
      const outcome = await requestApproval({
        gatewayUrl: config.gatewayUrl,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        target: config.target ?? config.agentId,
        actionType: name,
        params: handlerArgs,
        actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
        timeoutMs: config.timeoutMs,
        intervalMs: config.intervalMs,
      })

      if (outcome.outcome === "approved") {
        return originalHandler(handlerArgs, extra)
      } else if (outcome.outcome === "refused") {
        return {
          content: [
            {
              type: "text",
              text: `Intyga Gateway Security Check Refused: ${outcome.reason}`,
            },
          ],
        }
      } else {
        return {
          content: [
            {
              type: "text",
              text: `Intyga Gateway Error: ${outcome.reason}`,
            },
          ],
        }
      }
    }

  /** Swap the handler argument of a registration call for a gated one. */
  const gateArgs = (args: unknown[]): unknown[] => {
    const handlerIndex = args.findIndex((arg) => typeof arg === "function")
    if (handlerIndex === -1) return args
    const name = typeof args[0] === "string" ? args[0] : ""
    const next = [...args]
    next[handlerIndex] = gate(name, args[handlerIndex] as ToolHandler)
    return next
  }

  /**
   * Patch the returned handle so `update({ callback })` re-gates the replacement. Without this, one
   * `update` call after registration hands back an ungated tool.
   */
  const gateUpdates = (name: string, registered: unknown): unknown => {
    if (typeof registered !== "object" || registered === null) return registered
    const handle = registered as { update?: (updates: Record<string, unknown>) => unknown }
    if (typeof handle.update !== "function") return registered
    const originalUpdate = handle.update.bind(handle)
    handle.update = (updates: Record<string, unknown>) => {
      if (typeof updates?.callback !== "function") return originalUpdate(updates)
      // A rename in the same call changes which policy rule applies, so gate against the new name.
      const gatedName = typeof updates.name === "string" ? updates.name : name
      return originalUpdate({ ...updates, callback: gate(gatedName, updates.callback as ToolHandler) })
    }
    return registered
  }

  const originalTool = server.tool.bind(server)
  server.tool = ((...args: unknown[]) =>
    gateUpdates(
      typeof args[0] === "string" ? args[0] : "",
      (originalTool as (...a: unknown[]) => unknown)(...gateArgs(args)),
    )) as unknown as typeof originalTool

  // Guarded: `registerTool` arrived in a later @modelcontextprotocol/sdk than `tool`, so a server
  // that predates it (or a test double) simply has nothing to patch here.
  if (typeof server.registerTool === "function") {
    const originalRegisterTool = server.registerTool.bind(server)
    server.registerTool = ((...args: unknown[]) =>
      gateUpdates(
        typeof args[0] === "string" ? args[0] : "",
        (originalRegisterTool as (...a: unknown[]) => unknown)(...gateArgs(args)),
      )) as unknown as typeof originalRegisterTool
  }
}
