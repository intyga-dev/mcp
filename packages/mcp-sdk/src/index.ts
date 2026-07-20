import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { evaluatePolicy } from "./policy.js"

export { evaluatePolicy } from "./policy.js"
export type { PolicyContext, PolicyDecision, PolicyManifest, PolicyRule } from "./policy.js"

export interface SakraConfig {
  gatewayUrl: string
  clientId: string
  clientSecret: string
  agentId: string
  enforcement?: "local-first" | "gateway-enforced"
  localPolicyJson?: string
}

export function sakrafyServer(server: McpServer, config: SakraConfig) {
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
              text: `Security Violation: Action '${name}' is denied by SÄKRA policy.`,
            },
          ],
        }
      }

      // Otherwise, request human approval (biometric step-up) via SÄKRA Gateway API
      try {
        // Authenticate with the gateway via OAuth Basic exchange to get a token
        const tokenRes = await fetch(`${config.gatewayUrl}/oauth/token`, {
          method: "POST",
          headers: {
            Authorization: `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64")}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: "grant_type=client_credentials",
        })

        if (!tokenRes.ok) {
          throw new Error(`Failed to authenticate with SÄKRA gateway (status ${tokenRes.status})`)
        }

        const { access_token } = (await tokenRes.json()) as {
          access_token: string
        }

        // Trigger the challenge request on the gateway
        const challengeRes = await fetch(`${config.gatewayUrl}/action/request`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            actionType: name,
            params: handlerArgs,
            actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(handlerArgs)}`,
          }),
        })

        if (!challengeRes.ok) {
          const errBody = (await challengeRes.json().catch(() => ({ error: undefined }))) as {
            error?: string
          }
          throw new Error(
            errBody.error ?? `Failed to request approval challenge (status ${challengeRes.status})`,
          )
        }

        const { nonce } = (await challengeRes.json()) as { nonce: string }

        // Enter the polling loop until the challenge is approved or denied
        let status = "PENDING"
        const pollIntervalMs = 2000
        const maxPollAttempts = 60 // 2 minutes timeout
        let attempts = 0

        while (status === "PENDING" && attempts < maxPollAttempts) {
          await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
          attempts++

          const checkRes = await fetch(`${config.gatewayUrl}/action/status/${nonce}`, {
            headers: {
              Authorization: `Bearer ${access_token}`,
            },
          })

          if (checkRes.ok) {
            const checkData = (await checkRes.json()) as { status: string }
            status = checkData.status
          }
        }

        if (status === "APPROVED") {
          // Consume the approved challenge
          const consumeRes = await fetch(`${config.gatewayUrl}/action/consume`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              nonce,
              actionType: name,
              params: handlerArgs,
            }),
          })

          if (!consumeRes.ok) {
            throw new Error(`Failed to consume approved signature challenge`)
          }

          // Execute the tool and return the output
          return originalHandler(handlerArgs, extra)
        } else {
          return {
            content: [
              {
                type: "text",
                text: `Security Violation: Action '${name}' was rejected or timed out (status: ${status}).`,
              },
            ],
          }
        }
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `SÄKRA Gateway Error: ${(err as Error).message}`,
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
