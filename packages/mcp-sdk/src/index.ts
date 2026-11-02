import { assertGatewayUrl } from "@intyga/sdk"
import {
  assertAgentV1Runtime,
  assertExecutionTrust,
  reportDispatched,
  requestApproval,
} from "./approval-client.js"
import { evaluatePolicy } from "./policy.js"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"

export {
  assertAgentV1Runtime,
  assertExecutionTrust,
  reportDispatched,
  requestApproval,
} from "./approval-client.js"
// The gateway-URL rule every Intyga client applies (https://, loopback http for local development),
// re-exported so the stdio proxy can refuse a bad URL at startup rather than on the first tool call.
export { assertGatewayUrl } from "@intyga/sdk"
export type { AgentV1Runtime, ApprovalOutcome, ApprovalRequest, ExecutionTrust } from "./approval-client.js"
export { evaluatePolicy } from "./policy.js"
export type { PolicyContext, PolicyDecision, PolicyManifest, PolicyRule } from "./policy.js"

export interface IntygaConfig {
  /** https:// only; http:// is accepted for a loopback host (local development) and nothing else. */
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
  /** RP-owned v1 PEP. Required when clientId identifies an AI_AGENT. */
  agentV1?: import("./approval-client.js").AgentV1Runtime
  /** RP-owned receipt trust for SERVICE/human credentials. Mutually exclusive with `agentV1`. */
  executionTrust?: import("./approval-client.js").ExecutionTrust
  /**
   * DEWP §4.7 execution evidence: after an approved tool call runs, report the dispatch so a
   * registered evidence source has `evidenceWithinSeconds` to confirm it took effect. Best effort —
   * the tool result is returned either way. Unset: no dispatch is reported.
   */
  reportDispatch?: { evidenceWithinSeconds: number }
}

type ToolHandler = (...args: unknown[]) => unknown
type RegisteredTool = {
  inputSchema?: unknown
  handler: unknown
  update: (updates: Record<string, unknown>) => unknown
}
type McpServerInternals = {
  _registeredTools?: Record<string, RegisteredTool>
  _createRegisteredTool?: (...args: unknown[]) => RegisteredTool
}

function sanitizedExtra(extra: unknown): unknown {
  if (typeof extra !== "object" || extra === null || Array.isArray(extra)) return extra
  const source = extra as Record<string, unknown>
  const meta = source._meta
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    const { _meta: _dropped, ...rest } = source
    return rest
  }
  const progressToken = (meta as Record<string, unknown>).progressToken
  const { _meta: _dropped, ...rest } = source
  return {
    ...rest,
    ...((typeof progressToken === "string" ||
      (typeof progressToken === "number" && Number.isFinite(progressToken))) && {
      _meta: { progressToken },
    }),
  }
}

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
  // Fail at wiring time, not on the first tool call: a plain-http gateway would carry the client
  // secret and every approval request in the clear.
  assertGatewayUrl(config.gatewayUrl)
  if ((config.agentV1 === undefined) === (config.executionTrust === undefined))
    throw new Error("INTYGA MCP execution requires exactly one of agentV1 or executionTrust")
  if (config.agentV1) assertAgentV1Runtime(config.agentV1)
  else assertExecutionTrust(config.executionTrust, "executionTrust")
  const internals = server as unknown as McpServerInternals
  if (
    Object.getPrototypeOf(server) !== McpServer.prototype ||
    server.constructor !== McpServer ||
    typeof internals._createRegisteredTool !== "function" ||
    !internals._registeredTools ||
    typeof internals._registeredTools !== "object"
  )
    throw new Error(
      "Unsupported @modelcontextprotocol/sdk McpServer internals; @intyga/mcp-sdk supports exactly 1.32.1 and refused to leave tools ungated",
    )

  const gatedHandlers = new WeakSet<object>()
  const runGate = async (
    name: string,
    handlerArgs: Record<string, unknown>,
    invoke: (boundArgs: Record<string, unknown>) => Promise<unknown>,
  ): Promise<unknown> => {
    // Bind the bytes sent for approval to the args handed to the tool. MCP arguments are JSON;
    // snapshot them before any await so another task cannot mutate the caller's object while a
    // human is deciding. A non-JSON value is refused rather than guessed into a signed action.
    let boundArgs: Record<string, unknown>
    try {
      const raw = JSON.stringify(handlerArgs)
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
        throw new Error("tool arguments must be a JSON object")
      boundArgs = parsed as Record<string, unknown>
    } catch {
      return {
        content: [{ type: "text", text: "INTYGA Gateway Error: tool arguments are not JSON" }],
        isError: true,
      }
    }
    // 1. Evaluate policy (local-first check)
    const decision = evaluatePolicy(name, boundArgs, config)

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
      params: boundArgs,
      actionDescription: `Authorize action '${name}' with parameters: ${JSON.stringify(boundArgs)}`,
      timeoutMs: config.timeoutMs,
      intervalMs: config.intervalMs,
      agentV1: config.agentV1,
      executionTrust: config.executionTrust,
    })

    if (outcome.outcome === "approved") {
      try {
        return await invoke(boundArgs)
      } finally {
        // A handler that threw may still have sent the command, so the dispatch is reported either
        // way; the evidence source, not this process, says whether it took effect.
        if (config.reportDispatch)
          await reportDispatched(config, outcome.nonce, config.reportDispatch.evidenceWithinSeconds)
      }
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

  const gateHandler = (nameRef: { current: string }, original: unknown, hasInput: boolean): unknown => {
    if (typeof original !== "function" && (typeof original !== "object" || original === null))
      throw new Error(`Unsupported handler for MCP tool '${nameRef.current}'; refusing registration`)
    if (typeof original === "object" && gatedHandlers.has(original)) return original
    if (typeof original === "function") {
      if (gatedHandlers.has(original)) return original
      const wrapped: ToolHandler = hasInput
        ? async (args, extra) =>
            runGate(nameRef.current, args as Record<string, unknown>, (bound) =>
              Promise.resolve((original as ToolHandler)(bound, sanitizedExtra(extra))),
            )
        : async (extra) =>
            runGate(nameRef.current, {}, () =>
              Promise.resolve((original as ToolHandler)(sanitizedExtra(extra))),
            )
      gatedHandlers.add(wrapped)
      return wrapped
    }
    const task = original as { createTask?: ToolHandler }
    if (typeof task.createTask !== "function")
      throw new Error(`Unsupported handler object for MCP tool '${nameRef.current}'; refusing registration`)
    const createTask = task.createTask.bind(task)
    const wrapped = new Proxy(task, {
      get(target, property, receiver) {
        if (property !== "createTask") return Reflect.get(target, property, receiver)
        return hasInput
          ? async (args: unknown, extra: unknown) =>
              runGate(nameRef.current, args as Record<string, unknown>, (bound) =>
                Promise.resolve(createTask(bound, sanitizedExtra(extra))),
              )
          : async (extra: unknown) =>
              runGate(nameRef.current, {}, () => Promise.resolve(createTask(sanitizedExtra(extra))))
      },
    })
    gatedHandlers.add(wrapped)
    return wrapped
  }

  const secureRegistered = (registered: RegisteredTool, initialName: string): RegisteredTool => {
    const nameRef = { current: initialName }
    let rawHandler = registered.handler
    let hasInput = registered.inputSchema !== undefined
    registered.handler = gateHandler(nameRef, rawHandler, hasInput)
    const originalUpdate = registered.update.bind(registered)
    registered.update = (updates) => {
      const nextName = typeof updates.name === "string" ? updates.name : nameRef.current
      if (updates.callback !== undefined) rawHandler = updates.callback
      if (updates.paramsSchema !== undefined) hasInput = true
      const handlerChanged = updates.callback !== undefined || updates.paramsSchema !== undefined
      const next = !handlerChanged
        ? updates
        : {
            ...updates,
            callback: gateHandler(nameRef, rawHandler, hasInput),
          }
      const result = originalUpdate(next)
      nameRef.current = nextName
      return result
    }
    return registered
  }

  // Secure tools registered before wrapping, then intercept the one creation primitive used by
  // tool(), registerTool() and experimental.tasks.registerToolTask() in MCP SDK 1.32.1.
  for (const [name, registered] of Object.entries(internals._registeredTools))
    secureRegistered(registered, name)
  const originalCreate = internals._createRegisteredTool.bind(server)
  internals._createRegisteredTool = ((...args: unknown[]) => {
    const name = typeof args[0] === "string" ? args[0] : ""
    const registered = originalCreate(...args)
    return secureRegistered(registered, name)
  }) as typeof internals._createRegisteredTool

  return server
}
