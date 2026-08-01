// The polling loop only ever runs its interesting branches when the gateway is misbehaving — which
// is precisely when nobody is watching. These pin down the difference between "a blip we ride out"
// and "the gateway is gone", because conflating the two would record a human decision that never
// happened.

import assert from "node:assert/strict"
import { test } from "node:test"
import { requestApproval } from "./approval-client.ts"

const BASE = {
  gatewayUrl: "http://gw.example",
  clientId: "id",
  clientSecret: "secret",
  target: "prod-payments",
  actionType: "transfer",
  params: { amount: 5000 },
  intervalMs: 1, // keep the tests fast; the loop's shape is what matters, not the wall clock
}

type StatusStep = { status: string } | { fail: true } | { httpStatus: number }

/**
 * Stub the whole round trip. Token and challenge always succeed; `steps` drives one status check
 * each, so a test can spell out exactly what sequence of gateway behaviour it wants.
 */
function stubGateway(steps: StatusStep[], opts: { consumeOk?: boolean } = {}) {
  const original = globalThis.fetch
  let statusCalls = 0
  const json = (body: unknown, ok = true, status = 200) =>
    ({ ok, status, json: async () => body }) as unknown as Response

  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    // These are the AGENT-facing routes. The client used to call the console step-up endpoints
    // (/action/request, /action/status, /action/consume), which are gated on env.metricsToken and
    // 401 for an agent token — so the whole round trip could never complete. A stub that answers
    // whatever the client happens to ask for cannot catch that, which is why these match the real
    // paths exactly.
    if (u.endsWith("/oauth/token")) return json({ access_token: "tok" })
    if (u.endsWith("/authorize/verify")) {
      const ok = opts.consumeOk ?? true
      return json({ ok, reason: ok ? undefined : "already consumed" }, ok, ok ? 200 : 409)
    }
    if (u.endsWith("/authorize")) return json({ nonce: "n-1", status: "PENDING" })
    if (u.includes("/authorize/")) {
      const step = steps[Math.min(statusCalls++, steps.length - 1)]!
      if ("fail" in step) throw new Error("socket hang up")
      if ("httpStatus" in step) return json({}, false, step.httpStatus)
      return json({ status: step.status })
    }
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  return {
    restore: () => {
      globalThis.fetch = original
    },
    statusCalls: () => statusCalls,
  }
}

test("a transient failure mid-wait is ridden out and the approval still lands", async (t) => {
  const gw = stubGateway([{ fail: true }, { status: "PENDING" }, { status: "APPROVED" }])
  t.after(gw.restore)

  // The human is still deciding; one dropped socket must not throw their decision away.
  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "approved")
})

test("a 502 counts as a blip, not as a verdict", async (t) => {
  const gw = stubGateway([{ httpStatus: 502 }, { status: "APPROVED" }])
  t.after(gw.restore)

  // A non-2xx body carries no status field — treating it as a resolution would end the wait on noise.
  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "approved")
})

test("five consecutive failures are reported as a gateway error, not as a refusal", async (t) => {
  const gw = stubGateway([{ fail: true }])
  t.after(gw.restore)

  const r = await requestApproval(BASE)
  // This distinction is the whole point: `refused` would tell an operator a human declined an action
  // that no human ever saw, and that claim would land in the audit trail.
  assert.equal(r.outcome, "error")
  assert.match(r.outcome === "error" ? r.reason : "", /5 consecutive failures/)
  assert.equal(gw.statusCalls(), 5, "should stop at the cutoff rather than polling to the deadline")
})

test("the failure counter resets after any successful check", async (t) => {
  // Four failures, a success, then four more: a flapping gateway must not accumulate its way to the
  // cutoff, or a long wait over a shaky link would abort a perfectly healthy approval.
  const gw = stubGateway([
    { fail: true },
    { fail: true },
    { fail: true },
    { fail: true },
    { status: "PENDING" },
    { fail: true },
    { fail: true },
    { fail: true },
    { fail: true },
    { status: "APPROVED" },
  ])
  t.after(gw.restore)

  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "approved")
})

test("a denial is surfaced as a refusal carrying its status", async (t) => {
  const gw = stubGateway([{ status: "DENIED" }])
  t.after(gw.restore)

  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "refused")
  assert.equal(r.outcome === "refused" ? r.status : "", "DENIED")
})

test("exhausting the deadline is a refusal, distinct from an unreachable gateway", async (t) => {
  const gw = stubGateway([{ status: "PENDING" }])
  t.after(gw.restore)

  const r = await requestApproval({ ...BASE, timeoutMs: 30 })
  assert.equal(r.outcome, "refused")
  assert.equal(r.outcome === "refused" ? r.status : "", "TIMED_OUT")
})

test("a consume that fails blocks the action even though the human approved", async (t) => {
  const gw = stubGateway([{ status: "APPROVED" }], { consumeOk: false })
  t.after(gw.restore)

  // A challenge we could not claim may already have been spent — treat it as unusable.
  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "error")
  assert.match(r.outcome === "error" ? r.reason : "", /consume/i)
})

// ─── The round trip must hit routes an agent token can actually authenticate to ──
//
// This client used to call /action/request, /action/status/:nonce and /action/consume — the CONSOLE
// step-up endpoints, gated on a constant-time compare against env.metricsToken rather than on
// verifyAgentToken. An OAuth agent token 401s on every one, so the advertised gate never completed a
// single approval. It failed closed, so nothing was authorized without a human; the gate simply did
// not work. The tempting "fix" — handing agents metricsToken — would also unlock /internal/metrics
// and every console step-up in the deployment, so the routes are what had to change.
test("the round trip uses the agent-facing routes and binds the target on both calls", async () => {
  const original = globalThis.fetch
  const seen: { url: string; body: Record<string, unknown> | undefined }[] = []
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    let body: Record<string, unknown> | undefined
    try {
      body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
    } catch {
      body = undefined // the token call is form-encoded
    }
    seen.push({ url: u, body })
    const json = (b: unknown) => ({ ok: true, status: 200, json: async () => b }) as unknown as Response
    if (u.endsWith("/oauth/token")) return json({ access_token: "tok" })
    if (u.endsWith("/authorize/verify")) return json({ ok: true })
    if (u.endsWith("/authorize")) return json({ nonce: "n-1", status: "PENDING" })
    if (u.includes("/authorize/")) return json({ status: "APPROVED" })
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  try {
    const r = await requestApproval({ ...BASE, timeoutMs: 200 })
    assert.equal(r.outcome, "approved")

    const paths = seen.map((c) => new URL(c.url).pathname)
    assert.deepEqual(paths, ["/oauth/token", "/authorize", "/authorize/n-1", "/authorize/verify"])
    // No console step-up endpoint may appear anywhere in the round trip.
    assert.equal(
      paths.some((p) => p.startsWith("/action/")),
      false,
      "the round trip still calls a console step-up endpoint an agent token cannot authenticate to",
    )

    // DIV §3 Invariant 5: target must be bound on the challenge AND on the redemption. Omitting it
    // on authorize makes the gateway sign target="global"; omitting it on verify is a 400, which
    // made single-use redemption unreachable.
    const authorize = seen.find((c) => new URL(c.url).pathname === "/authorize")!
    const verify = seen.find((c) => new URL(c.url).pathname === "/authorize/verify")!
    assert.equal(authorize.body?.target, "prod-payments")
    assert.equal(verify.body?.target, "prod-payments")
    assert.equal(verify.body?.nonce, "n-1")
  } finally {
    globalThis.fetch = original
  }
})

test("a 200 that does not confirm the redemption is still a refusal", async () => {
  // The gateway reports a params/target mismatch or an already-spent nonce in the BODY, not the
  // status line. Reading only res.ok would execute on an approval that was never actually claimed.
  const original = globalThis.fetch
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    const json = (b: unknown) => ({ ok: true, status: 200, json: async () => b }) as unknown as Response
    if (u.endsWith("/oauth/token")) return json({ access_token: "tok" })
    if (u.endsWith("/authorize/verify")) return json({ ok: false, reason: "params do not match" })
    if (u.endsWith("/authorize")) return json({ nonce: "n-1", status: "PENDING" })
    if (u.includes("/authorize/")) return json({ status: "APPROVED" })
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  try {
    const r = await requestApproval({ ...BASE, timeoutMs: 200 })
    assert.notEqual(r.outcome, "approved")
    assert.match((r as { reason: string }).reason, /params do not match/)
  } finally {
    globalThis.fetch = original
  }
})
