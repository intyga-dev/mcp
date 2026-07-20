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
    if (u.endsWith("/oauth/token")) return json({ access_token: "tok" })
    if (u.endsWith("/action/request")) return json({ nonce: "n-1" })
    if (u.includes("/action/status/")) {
      const step = steps[Math.min(statusCalls++, steps.length - 1)]!
      if ("fail" in step) throw new Error("socket hang up")
      if ("httpStatus" in step) return json({}, false, step.httpStatus)
      return json({ status: step.status })
    }
    return json({}, opts.consumeOk ?? true, opts.consumeOk === false ? 409 : 200)
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
