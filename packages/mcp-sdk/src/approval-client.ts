import { z } from "zod"

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
}

export type ApprovalOutcome =
  | { outcome: "approved"; nonce: string }
  | { outcome: "refused"; status: string; reason: string }
  | { outcome: "error"; reason: string }

/** Consecutive failed status checks tolerated before we call the gateway unreachable. */
const MAX_POLL_ERRORS = 5

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function getToken(req: ApprovalRequest): Promise<string> {
  const basic = Buffer.from(`${req.clientId}:${req.clientSecret}`).toString("base64")
  const res = await fetch(`${req.gatewayUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  })
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
async function openChallenge(req: ApprovalRequest, token: string): Promise<string> {
  const res = await fetch(`${req.gatewayUrl}/authorize`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      target: req.target,
      actionType: req.actionType,
      params: req.params,
      actionDescription:
        req.actionDescription ??
        `Authorize action '${req.actionType}' with parameters: ${JSON.stringify(req.params)}`,
    }),
  })
  if (!res.ok) {
    const parsed = publicApiError.safeParse(await res.json().catch(() => null))
    if (!parsed.success) throw new Error(`Failed to request approval challenge (status ${res.status})`)
    const { code, message, requestId } = parsed.data.error
    throw new Error(
      `Failed to request approval challenge (status ${res.status}, ${code}): ${message}` +
        (requestId ? ` [requestId ${requestId}]` : ""),
    )
  }
  return ((await res.json()) as { nonce: string }).nonce
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
): Promise<{ status: string; token: string }> {
  const timeoutMs = req.timeoutMs ?? 120_000
  const intervalMs = req.intervalMs ?? 2_000
  const deadline = Date.now() + timeoutMs
  let consecutiveErrors = 0
  let token = initialToken
  let reauthenticated = false

  while (Date.now() < deadline) {
    await sleep(intervalMs)
    try {
      const res = await fetch(`${req.gatewayUrl}/authorize/${encodeURIComponent(nonce)}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (res.status === 401 && !reauthenticated) {
        reauthenticated = true
        token = await getToken(req)
        continue
      }
      if (!res.ok) throw new Error(`status check failed (${res.status})`)
      const { status } = (await res.json()) as { status: string }
      consecutiveErrors = 0
      if (status !== "PENDING") return { status, token }
    } catch (err) {
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
  const res = await fetch(`${req.gatewayUrl}/authorize/verify`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    // `target` is REQUIRED by the authorizationConsume schema — omitting it is a 400, which would
    // make redemption unreachable and leave the approval replayable for the rest of its TTL.
    body: JSON.stringify({ nonce, target: req.target, actionType: req.actionType, params: req.params }),
  })
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
    const initialToken = await getToken(req)
    const nonce = await openChallenge(req, initialToken)
    const { status, token } = await waitForVerdict(req, initialToken, nonce)

    if (status !== "APPROVED") {
      return {
        outcome: "refused",
        status,
        reason: `Action '${req.actionType}' was rejected or timed out (status: ${status}).`,
      }
    }

    await consume(req, token, nonce)
    return { outcome: "approved", nonce }
  } catch (err) {
    return { outcome: "error", reason: (err as Error).message }
  }
}
