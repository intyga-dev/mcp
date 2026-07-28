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
  enforcement?: "local-first" | "gateway-enforced"
  localPolicyJson?: string
}

export function intygafyServer(server: McpServer, config: IntygaConfig) {
  const originalTool = server.tool.bind(server)

  server.tool = ((...args: Parameters<typeof originalTool>) => {
    const handlerIndex = args.findIndex((arg) => typeof arg === "function")
    if (handlerIndex === -1) {
      return (originalTool as (...args: unknown[]) => unknown)(...args)
    }

    const name = args[0] as string
    const originalHandler = args[handlerIndex] as (...args: unknown[]) => Promise<unknown>

    const secureHandler = async (handlerArgs: Record<string, unknown>, extra: unknown): Promise<unknown> => {
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
        actionType: name,
        params: handlerArgs,
        actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
      })

      if (outcome.outcome === "approved") {
        return originalHandler(handlerArgs, extra)
      } else if (outcome.outcome === "refused") {
        return {
          content: [
            {
              type: "text",
              text: `Security Violation: ${outcome.reason}`,
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

    // Replace the callback handler argument with our secured handler
    const newArgs = [...args]
    newArgs[handlerIndex] = secureHandler as unknown as (typeof args)[number]

    return (originalTool as (...args: unknown[]) => unknown)(...newArgs)
  }) as unknown as typeof originalTool
}
