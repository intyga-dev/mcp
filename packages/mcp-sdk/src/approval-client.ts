import { z } from "zod"
import {
  agentConfigDigest,
  assertGatewayUrl,
  GATEWAY_TIMEOUT_MS,
  isRedirect,
  redirectHint,
  verifyAgentForExecution,
  type AgentIntentContext,
  type AgentSessionState,
  type ApproverTrustAnchor,
  type LiveAgentConfig,
} from "@intyga/sdk"

type AgentInput = {
  action: AgentIntentContext["action"]
  delegatedBy: string | null
  session: AgentIntentContext["session"]
}

/** RP-owned inputs and atomic state operations. None may be sourced from the MCP caller or receipt. */
export interface AgentV1Runtime {
  requesterDid: string
  approvers: ApproverTrustAnchor
  verifier: NonNullable<Parameters<typeof verifyAgentForExecution>[4]>
  prepare(actionType: string, params: Record<string, unknown>): Promise<AgentInput>
  liveConfig(): Promise<LiveAgentConfig>
  readState(sessionId: string): Promise<AgentSessionState>
  /** Atomically compare the prior state, reserve aggregate budget, consume nonce and save the head.
   * Return false on conflict, duplicate nonce or budget refusal. Never return true without persisting. */
  reserve(input: {
    nonce: string
    sessionId: string
    prior: AgentSessionState
    next: AgentSessionState
    amount: AgentIntentContext["action"]["amount"]
  }): Promise<boolean>
}

// The out-of-band approval round trip: authenticate, raise a challenge, wait for the human, then
// consume it exactly once before the action runs. Both enforcement paths — the in-process wrapper
// (`intygafyServer`) and the stdio proxy — share this, because when it existed twice the two copies
// had already drifted and the fragile polling loop had to be found and fixed twice.
//
// Fail-closed throughout: this returns "approved" only when a human actually signed AND the
// challenge was successfully consumed. Every other outcome — denial, timeout, transport failure,
// a replayed nonce — is a refusal, and the caller must not execute.

/**
 * The gateway rewrites EVERY non-2xx JSON body into one envelope at its response boundary
 * (`apps/gateway/src/public-error.ts`, documented in `docs/API.md`), so `error` is an object, not a
 * string. Read as `{ error?: string }` it stringified to the literal `[object Object]` and threw
 * away `requestId` — the only handle correlating a refusal with the gateway-side log.
 *
 * Mirrored here rather than imported from `@intyga/mcp-schemas`: this package publishes standalone
 * and must not carry a workspace dependency. If `PublicApiError` changes shape, grep for it.
 */
const publicApiError = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    requestId: z.string().optional(),
  }),
})

export interface ApprovalRequest {
  /** https:// only; http:// is accepted for a loopback host (local development) and nothing else. */
  gatewayUrl: string
  clientId: string
  clientSecret: string
  /**
   * The relying party / execution environment this approval is bound to (DIV §3 Invariant 5, Target
   * Isolation). REQUIRED, and asserted from the agent's own identity.
   *
   * Omitting it is not neutral: the gateway defaults a missing target to the literal `"global"`, so
   * the signed intent binds no environment at all and an approval raised here verifies at every
   * other relying party in the tenant. That is precisely the cross-service replay Target Isolation
   * exists to prevent.
   */
  target: string
  actionType: string
  params: Record<string, unknown>
  actionDescription?: string
  /** How long to wait for the human, in ms. Default 2 minutes. */
  timeoutMs?: number
  /** How often to re-check, in ms. Default 2 seconds. */
  intervalMs?: number
  /** Mandatory for AI_AGENT keys. Provides v1 context and the RP's execution-time PEP. */
  agentV1?: AgentV1Runtime
}

export type ApprovalOutcome =
  | { outcome: "approved"; nonce: string }
  | { outcome: "refused"; status: string; reason: string }
  | { outcome: "error"; reason: string }

/** Consecutive failed status checks tolerated before we call the gateway unreachable. */
const MAX_POLL_ERRORS = 5

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function fromRp<T>(operation: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run()
  } catch {
    // RP adapters may throw DB errors containing private connection details. The MCP caller is
    // untrusted; report only which local check failed, never the adapter's raw exception.
    throw new Error(`RP ${operation} unavailable`)
  }
}

/**
 * A redirect from the gateway. Never followed (`redirect: "manual"` on every request below): fetch
 * re-sends a POST body on a 307/308, and these bodies carry the approval request and the client
 * credentials' token. Its own class so the status poll can stop at once instead of counting it as a
 * transient blip.
 */
class RedirectRefused extends Error {}

/** Every gateway request: never follow a redirect, and bound the wait (matches IntygaClient). */
function gatewayFetch(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS) })
}

function refuseRedirect(res: Response, op: string): void {
  if (isRedirect(res)) throw new RedirectRefused(`${op} failed (status ${res.status}): ${redirectHint(res)}`)
}

async function getToken(req: ApprovalRequest): Promise<string> {
  const basic = Buffer.from(`${req.clientId}:${req.clientSecret}`).toString("base64")
  const res = await gatewayFetch(`${req.gatewayUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  })
  refuseRedirect(res, "Authentication with the Intyga gateway")
  if (!res.ok) throw new Error(`Failed to authenticate with Intyga gateway (status ${res.status})`)
  return ((await res.json()) as { access_token: string }).access_token
}

/**
 * Raise the challenge on the AGENT-facing route.
 *
 * `/action/request`, `/action/status/:nonce` and `/action/consume` are the CONSOLE step-up endpoints.
 * They are gated on `internalOk(req)`, a constant-time comparison against `env.metricsToken` — not on
 * `verifyAgentToken` — so an OAuth agent token 401s on every one of them and this whole round trip
 * could never complete. (It failed closed, so nothing was authorized without a human; the gate simply
 * did not work.) The bodies were wrong too: `actionRequest` requires `actorDid` and `summary`, and
 * `actionConsume` requires `actorDid` and a UUID `tenantId`.
 *
 * The fix is to use the routes built for this caller, not to hand an agent `metricsToken` — that
 * token also unlocks `/internal/metrics`, `/metrics/usage/:tenantId`, and every console step-up
 * request/status/consume for the whole deployment.
 */
async function openChallenge(
  req: ApprovalRequest,
  token: string,
  agentInput?: AgentInput & { configDigest: string },
): Promise<{ nonce: string; agentContext?: AgentIntentContext }> {
  const res = await gatewayFetch(`${req.gatewayUrl}/authorize`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      target: req.target,
      actionType: req.actionType,
      params: req.params,
      ...(agentInput ? { agentContext: agentInput } : {}),
      actionDescription:
        req.actionDescription ??
        `Authorize action '${req.actionType}' with parameters: ${JSON.stringify(req.params)}`,
    }),
  })
  refuseRedirect(res, "Requesting the approval challenge")
  if (!res.ok) {
    const parsed = publicApiError.safeParse(await res.json().catch(() => null))
    if (!parsed.success) throw new Error(`Failed to request approval challenge (status ${res.status})`)
    const { code, message, requestId } = parsed.data.error
    throw new Error(
      `Failed to request approval challenge (status ${res.status}, ${code}): ${message}` +
        (requestId ? ` [requestId ${requestId}]` : ""),
    )
  }
  return (await res.json()) as { nonce: string; agentContext?: AgentIntentContext }
}

/**
 * Wait for the human's verdict.
 *
 * A person's decision can easily outlast a momentary 502 or socket hangup, so a single failed check
 * must not throw the whole wait away — that would discard an approval they may already have given.
 * We tolerate blips and give up only once the gateway looks genuinely unreachable, which is also
 * why a persistently failing gateway now reports that instead of quietly counting down to "timed
 * out" and blaming the human.
 *
 * A 401 mid-wait is a different thing from a blip: the agent token has outlived its TTL (a
 * `timeoutMs` longer than the token's life does this). It is answered by re-exchanging the client
 * credentials ONCE and carrying on — the returned token is the one still valid at the end, which
 * `consume` must use. A second 401 after that is an ordinary failure, so a revoked key cannot turn
 * the wait into an exchange loop.
 */
async function waitForVerdict(
  req: ApprovalRequest,
  initialToken: string,
  nonce: string,
): Promise<{ status: string; token: string; receipt?: unknown }> {
  const timeoutMs = req.timeoutMs ?? 120_000
  const intervalMs = req.intervalMs ?? 2_000
  const deadline = Date.now() + timeoutMs
  let consecutiveErrors = 0
  let token = initialToken
  let reauthenticated = false

  while (Date.now() < deadline) {
    await sleep(intervalMs)
    try {
      const res = await gatewayFetch(`${req.gatewayUrl}/authorize/${encodeURIComponent(nonce)}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      refuseRedirect(res, "Approval status check")
      if (res.status === 401 && !reauthenticated) {
        reauthenticated = true
        token = await getToken(req)
        continue
      }
      if (!res.ok) throw new Error(`status check failed (${res.status})`)
      const { status, receipt } = (await res.json()) as { status: string; receipt?: unknown }
      consecutiveErrors = 0
      if (status !== "PENDING") return { status, token, receipt }
    } catch (err) {
      // A redirect is configuration, not a blip: retrying cannot fix it.
      if (err instanceof RedirectRefused) throw err
      if (++consecutiveErrors >= MAX_POLL_ERRORS) {
        throw new Error(
          `Approval status could not be read after ${MAX_POLL_ERRORS} consecutive failures: ${(err as Error).message}`,
        )
      }
    }
  }
  return { status: "TIMED_OUT", token }
}

/**
 * Burn the approval so it cannot be replayed, re-binding the exact params that are about to run.
 * If this fails the action does NOT proceed, even though a human approved: a challenge we could not
 * claim may already have been spent.
 */
async function consume(req: ApprovalRequest, token: string, nonce: string): Promise<void> {
  const res = await gatewayFetch(`${req.gatewayUrl}/authorize/verify`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    // `target` is REQUIRED by the authorizationConsume schema — omitting it is a 400, which would
    // make redemption unreachable and leave the approval replayable for the rest of its TTL.
    body: JSON.stringify({ nonce, target: req.target, actionType: req.actionType, params: req.params }),
  })
  refuseRedirect(res, "Consuming the approved challenge")
  if (!res.ok) throw new Error("Failed to consume approved signature challenge")
  // A 200 is not automatically a redemption: the gateway reports a params/target mismatch or an
  // already-spent nonce in the body. Executing on that would defeat the re-binding this call is for.
  const body = (await res.json().catch(() => ({}))) as { ok?: boolean; reason?: string }
  if (body.ok !== true) {
    throw new Error(`Approval could not be consumed: ${body.reason ?? "gateway refused the redemption"}`)
  }
}

/** Run the full approval round trip. Never throws — every failure is reported as a refusal. */
export async function requestApproval(req: ApprovalRequest): Promise<ApprovalOutcome> {
  try {
    const params: unknown = JSON.parse(JSON.stringify(req.params))
    if (typeof params !== "object" || params === null || Array.isArray(params))
      throw new Error("approval parameters must be a JSON object")
    // Refused before any credential is sent: https:// only, loopback http for local development.
    const boundReq = {
      ...req,
      gatewayUrl: assertGatewayUrl(req.gatewayUrl),
      params: params as Record<string, unknown>,
    }
    const initialToken = await getToken(boundReq)
    const runtime = boundReq.agentV1
    const prepared = runtime
      ? await fromRp("agent context", () =>
          runtime.prepare(
            boundReq.actionType,
            JSON.parse(JSON.stringify(boundReq.params)) as Record<string, unknown>,
          ),
        )
      : undefined
    const agentInput =
      runtime && prepared
        ? {
            ...prepared,
            configDigest: agentConfigDigest(
              await fromRp("live agent configuration", () => runtime.liveConfig()),
            ),
          }
        : undefined
    const opened = await openChallenge(boundReq, initialToken, agentInput)
    const { nonce } = opened
    const { status, token, receipt } = await waitForVerdict(boundReq, initialToken, nonce)

    if (status !== "APPROVED") {
      return {
        outcome: "refused",
        status,
        reason: `Action '${boundReq.actionType}' was rejected or timed out (status: ${status}).`,
      }
    }

    if (runtime) {
      // The issuer's nbf and registered DID are retained from the opening response, never copied
      // from the receipt being verified. The other claims are the RP's own prepared context.
      const issued = opened.agentContext
      if (
        !issued ||
        !agentInput ||
        issued.agent.label !== runtime.requesterDid ||
        issued.agent.configDigest !== agentInput.configDigest ||
        issued.agent.delegatedBy !== agentInput.delegatedBy ||
        JSON.stringify(issued.action) !== JSON.stringify(agentInput.action) ||
        JSON.stringify(issued.session) !== JSON.stringify(agentInput.session) ||
        !receipt
      )
        throw new Error("Gateway did not return the requested v1 agent context and receipt")

      // Gateway redemption is single-use. A later local refusal burns the approval without running
      // the tool; that is the safe outcome when configuration, trust or session state changed.
      await consume(boundReq, token, nonce)
      const prior = await fromRp("agent session state", () => runtime.readState(issued.session.id))
      const expected = {
        approvers: runtime.approvers,
        target: boundReq.target,
        actionType: boundReq.actionType,
        params: boundReq.params,
        nonce,
        requesterDid: runtime.requesterDid,
        agentContext: issued,
      }
      const proof = verifyAgentForExecution(
        receipt as Parameters<typeof verifyAgentForExecution>[0],
        expected,
        await fromRp("live agent configuration", () => runtime.liveConfig()),
        prior,
        runtime.verifier,
      )
      if (!proof.ok || !proof.nextHead)
        throw new Error(`v1 agent receipt refused: ${proof.reason ?? "no head"}`)
      const nextHead = proof.nextHead
      const reserved = await fromRp("agent reservation", () =>
        runtime.reserve({
          nonce,
          sessionId: issued.session.id,
          prior,
          next: { head: nextHead, seq: issued.session.seq, aggregate: issued.session.aggregate },
          amount: issued.action.amount,
        }),
      )
      if (!reserved) throw new Error("v1 agent session, nonce or budget reservation refused")
    } else {
      await consume(boundReq, token, nonce)
    }
    return { outcome: "approved", nonce }
  } catch (err) {
    return { outcome: "error", reason: (err as Error).message }
  }
}
