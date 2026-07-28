// The out-of-band approval round trip: authenticate, raise a challenge, wait for the human, then
// consume it exactly once before the action runs. Both enforcement paths — the in-process wrapper
// (`intygafyServer`) and the stdio proxy — share this, because when it existed twice the two copies
// had already drifted and the fragile polling loop had to be found and fixed twice.
//
// Fail-closed throughout: this returns "approved" only when a human actually signed AND the
// challenge was successfully consumed. Every other outcome — denial, timeout, transport failure,
// a replayed nonce — is a refusal, and the caller must not execute.

export interface ApprovalRequest {
  gatewayUrl: string
  clientId: string
  clientSecret: string
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

async function openChallenge(req: ApprovalRequest, token: string): Promise<string> {
  const res = await fetch(`${req.gatewayUrl}/action/request`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      actionType: req.actionType,
      params: req.params,
      actionDescription:
        req.actionDescription ??
        `Authorize action '${req.actionType}' with parameters: ${JSON.stringify(req.params)}`,
    }),
  })
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error ?? `Failed to request approval challenge (status ${res.status})`)
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
 */
async function waitForVerdict(req: ApprovalRequest, token: string, nonce: string): Promise<string> {
  const timeoutMs = req.timeoutMs ?? 120_000
  const intervalMs = req.intervalMs ?? 2_000
  const deadline = Date.now() + timeoutMs
  let consecutiveErrors = 0

  while (Date.now() < deadline) {
    await sleep(intervalMs)
    try {
      const res = await fetch(`${req.gatewayUrl}/action/status/${encodeURIComponent(nonce)}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`status check failed (${res.status})`)
      const { status } = (await res.json()) as { status: string }
      consecutiveErrors = 0
      if (status !== "PENDING") return status
    } catch (err) {
      if (++consecutiveErrors >= MAX_POLL_ERRORS) {
        throw new Error(
          `Approval status could not be read after ${MAX_POLL_ERRORS} consecutive failures: ${(err as Error).message}`,
        )
      }
    }
  }
  return "TIMED_OUT"
}

/**
 * Burn the approval so it cannot be replayed, re-binding the exact params that are about to run.
 * If this fails the action does NOT proceed, even though a human approved: a challenge we could not
 * claim may already have been spent.
 */
async function consume(req: ApprovalRequest, token: string, nonce: string): Promise<void> {
  const res = await fetch(`${req.gatewayUrl}/action/consume`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ nonce, actionType: req.actionType, params: req.params }),
  })
  if (!res.ok) throw new Error("Failed to consume approved signature challenge")
}

/** Run the full approval round trip. Never throws — every failure is reported as a refusal. */
export async function requestApproval(req: ApprovalRequest): Promise<ApprovalOutcome> {
  try {
    const token = await getToken(req)
    const nonce = await openChallenge(req, token)
    const status = await waitForVerdict(req, token, nonce)

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
