// The polling loop only ever runs its interesting branches when the gateway is misbehaving — which
// is precisely when nobody is watching. These pin down the difference between "a blip we ride out"
// and "the gateway is gone", because conflating the two would record a human decision that never
// happened.

import assert from "node:assert/strict"
import crypto from "node:crypto"
import http from "node:http"
import type { AddressInfo } from "node:net"
import { test } from "node:test"
import { agentConfigDigest, canonicalIntentPayload, type AgentIntentContext } from "@intyga/sdk"
import {
  assertExecutionTrust,
  reportDispatched,
  requestApproval,
  type AgentV1Runtime,
} from "./approval-client.ts"

const BASE = {
  gatewayUrl: "https://gw.example",
  clientId: "id",
  clientSecret: "secret",
  target: "prod-payments",
  actionType: "transfer",
  params: { amount: 5000 },
  intervalMs: 1, // keep the tests fast; the loop's shape is what matters, not the wall clock
  executionTrust: undefined as unknown as import("./approval-client.ts").ExecutionTrust,
}

test("dispatch reporting is best effort when authentication or transport throws", async (t) => {
  const originalFetch = globalThis.fetch
  t.after(() => {
    globalThis.fetch = originalFetch
  })
  globalThis.fetch = (async () => {
    throw new Error("private transport detail")
  }) as typeof fetch
  assert.equal(await reportDispatched(BASE, "dispatch-nonce", 30), false)
})

test("authentication refusal stops before approval credentials reach an action route", async (t) => {
  const originalFetch = globalThis.fetch
  t.after(() => {
    globalThis.fetch = originalFetch
  })
  const paths: string[] = []
  globalThis.fetch = (async (url: unknown) => {
    paths.push(new URL(String(url)).pathname)
    return { ok: false, status: 401, json: async () => ({}) } as unknown as Response
  }) as typeof fetch

  const result = await requestApproval(BASE)
  assert.deepEqual(paths, ["/oauth/token"])
  assert.equal(result.outcome, "error")
  assert.match(result.outcome === "error" ? result.reason : "", /authenticate.*status 401/i)
})

const SERVICE_KEYS = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
const SERVICE_PUBLIC_KEY = SERVICE_KEYS.publicKey.export({ format: "der", type: "spki" }).toString("base64")
const SERVICE_TENANT = "11111111-1111-4111-8111-111111111111"
const SERVICE_DID = "did:intyga:service:test"
const SERVICE_REQUIREMENT = {
  requiredApprovals: 1,
  requireHardwareKey: false,
  requesterCannotApprove: true,
}
const SIGNED_REQUIREMENT = {
  ...SERVICE_REQUIREMENT,
  allowedAaguids: [] as string[],
  excludedSignerDids: [] as string[],
  signerClass: "human" as const,
}
const SERVICE_TRUST = {
  tenantId: SERVICE_TENANT,
  requesterDid: SERVICE_DID,
  approvers: {
    dids: ["did:intyga:owner"],
    resolveKey: (did: string) => (did === "did:intyga:owner" ? SERVICE_PUBLIC_KEY : null),
  },
  requirement: SERVICE_REQUIREMENT,
}
BASE.executionTrust = SERVICE_TRUST

function serviceReceipt(nonce = "n-1") {
  const expiresAt = new Date(Date.now() + 180_000).toISOString()
  const actionDescription = `Authorize action '${BASE.actionType}' with parameters: ${JSON.stringify(BASE.params)}`
  const canonicalPayload = canonicalIntentPayload({
    tenantId: SERVICE_TENANT,
    target: BASE.target,
    actionType: BASE.actionType,
    display: actionDescription,
    params: BASE.params,
    requester: { did: SERVICE_DID, attestation: null },
    requirement: SIGNED_REQUIREMENT,
    nonce,
    expiresAt,
  })
  return {
    canonicalPayload,
    actionDescription,
    params: BASE.params,
    requester: { did: SERVICE_DID, attestation: null },
    signerDid: "did:intyga:owner",
    signerPublicKey: SERVICE_PUBLIC_KEY,
    signature: crypto
      .sign("sha256", Buffer.from(canonicalPayload), {
        key: SERVICE_KEYS.privateKey,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64"),
    sigAlg: "ES256" as const,
    verificationCode: "unused",
  }
}

type StatusStep = { status: string } | { fail: true } | { httpStatus: number }

/**
 * Stub the whole round trip. Token and challenge always succeed; `steps` drives one status check
 * each, so a test can spell out exactly what sequence of gateway behaviour it wants. Each exchange
 * mints a distinct token (`tok-1`, `tok-2`, …) so a test can tell which one a later call carried.
 */
function stubGateway(steps: StatusStep[], opts: { consumeOk?: boolean } = {}) {
  const original = globalThis.fetch
  let statusCalls = 0
  let exchanges = 0
  let consumeBearer: string | undefined
  const json = (body: unknown, ok = true, status = 200) =>
    ({ ok, status, json: async () => body }) as unknown as Response

  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    // These are the AGENT-facing routes. The client used to call the console step-up endpoints
    // (/action/request, /action/status, /action/consume), which are gated on env.metricsToken and
    // 401 for an agent token — so the whole round trip could never complete. A stub that answers
    // whatever the client happens to ask for cannot catch that, which is why these match the real
    // paths exactly.
    if (u.endsWith("/oauth/token")) return json({ access_token: `tok-${++exchanges}` })
    if (u.endsWith("/authorize/verify")) {
      consumeBearer = (init?.headers as Record<string, string> | undefined)?.Authorization
      const ok = opts.consumeOk ?? true
      return json({ ok, reason: ok ? undefined : "already consumed" }, ok, ok ? 200 : 409)
    }
    if (u.endsWith("/authorize")) return json({ nonce: "n-1", status: "PENDING" })
    if (u.includes("/authorize/")) {
      const step = steps[Math.min(statusCalls++, steps.length - 1)]!
      if ("fail" in step) throw new Error("socket hang up")
      if ("httpStatus" in step) return json({}, false, step.httpStatus)
      return json({
        status: step.status,
        ...(step.status === "APPROVED" ? { receipt: serviceReceipt() } : {}),
      })
    }
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  return {
    restore: () => {
      globalThis.fetch = original
    },
    statusCalls: () => statusCalls,
    exchanges: () => exchanges,
    consumeBearer: () => consumeBearer,
  }
}

test("a transient failure mid-wait is ridden out and the approval still lands", async (t) => {
  const gw = stubGateway([{ fail: true }, { status: "PENDING" }, { status: "APPROVED" }])
  t.after(gw.restore)

  // The human is still deciding; one dropped socket must not throw their decision away.
  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "approved")
})

test("service receipt verification precedes consumption and enforces RP tenant and floor", async (t) => {
  const gw = stubGateway([{ status: "APPROVED" }])
  t.after(gw.restore)
  const wrongTenant = await requestApproval({
    ...BASE,
    executionTrust: { ...SERVICE_TRUST, tenantId: "22222222-2222-4222-8222-222222222222" },
  })
  assert.equal(wrongTenant.outcome, "error")
  assert.match(wrongTenant.outcome === "error" ? wrongTenant.reason : "", /tenant/i)
  assert.equal(gw.consumeBearer(), undefined, "deterministic proof failure must not consume")

  const weakFloor = await requestApproval({
    ...BASE,
    executionTrust: { ...SERVICE_TRUST, requirement: { requiredApprovals: 2 } },
  })
  assert.equal(weakFloor.outcome, "error")
  assert.match(weakFloor.outcome === "error" ? weakFloor.reason : "", /weaker|approval/i)
  assert.equal(gw.consumeBearer(), undefined)

  const missingExclusion = await requestApproval({
    ...BASE,
    executionTrust: {
      ...SERVICE_TRUST,
      requirement: {
        ...SERVICE_REQUIREMENT,
        excludedSignerDids: ["did:intyga:controller"],
      },
    },
  })
  assert.equal(missingExclusion.outcome, "error")
  assert.match(missingExclusion.outcome === "error" ? missingExclusion.reason : "", /weaker|exclusion/i)
  assert.equal(gw.consumeBearer(), undefined, "an unmet exclusion floor must not be stripped before verify")
})

test("execution trust validates and forwards a signed empty exclusion floor", async (t) => {
  const executionTrust = {
    ...SERVICE_TRUST,
    requirement: { ...SERVICE_REQUIREMENT, excludedSignerDids: [] },
  }
  assert.doesNotThrow(() => assertExecutionTrust(executionTrust))
  for (const excludedSignerDids of ["did:intyga:owner", ["not-a-did"], [7]]) {
    assert.throws(
      () =>
        assertExecutionTrust({
          ...SERVICE_TRUST,
          requirement: { ...SERVICE_REQUIREMENT, excludedSignerDids },
        }),
      /invalid policy-floor fields/,
    )
  }
  assert.throws(
    () =>
      assertExecutionTrust({
        ...SERVICE_TRUST,
        requirement: { ...SERVICE_REQUIREMENT, excludedSignerDids: [], unsupported: true },
      }),
    /unsupported execution floor fields/,
  )

  const gw = stubGateway([{ status: "APPROVED" }])
  t.after(gw.restore)
  const result = await requestApproval({ ...BASE, executionTrust })
  assert.equal(result.outcome, "approved", result.outcome === "error" ? result.reason : undefined)
  assert.equal(gw.consumeBearer(), "Bearer tok-1")
})

test("execution trust validates enrolled device keys and forwards them to both receipt checks (DIV §4.3.2)", async (t) => {
  for (const enrolledDeviceKeys of ["key", [""], [7], [null]]) {
    assert.throws(
      () => assertExecutionTrust({ ...SERVICE_TRUST, enrolledDeviceKeys } as never),
      /enrolledDeviceKeys must be an array of non-empty base64 keys/,
    )
  }
  const executionTrust = { ...SERVICE_TRUST, enrolledDeviceKeys: ["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"] }
  assert.doesNotThrow(() => assertExecutionTrust(executionTrust))
  // The receipt's signed policy does not require a device, so a supplied device-key list changes
  // nothing: the same receipt still verifies before and after consumption.
  const gw = stubGateway([{ status: "APPROVED" }])
  t.after(gw.restore)
  const result = await requestApproval({ ...BASE, executionTrust })
  assert.equal(result.outcome, "approved", result.outcome === "error" ? result.reason : undefined)
  assert.equal(gw.consumeBearer(), "Bearer tok-1")
})

test("service execution refuses AUTO_APPROVED even if verifier options try to allow it", async (t) => {
  const original = globalThis.fetch
  t.after(() => {
    globalThis.fetch = original
  })
  let consumed = false
  const signed = serviceReceipt()
  const automatic = {
    canonicalPayload: signed.canonicalPayload,
    actionDescription: signed.actionDescription,
    params: signed.params,
    requester: signed.requester,
    sigAlg: "AUTO_APPROVED" as const,
    verificationCode: "unused",
  }
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    if (u.endsWith("/oauth/token")) return Response.json({ access_token: "token" })
    if (u.endsWith("/authorize")) return Response.json({ nonce: "n-1" })
    if (u.endsWith("/authorize/verify")) {
      consumed = true
      return Response.json({ ok: true })
    }
    return Response.json({ status: "APPROVED", receipt: automatic })
  }) as typeof fetch
  const outcome = await requestApproval({
    ...BASE,
    executionTrust: { ...SERVICE_TRUST, verifier: { allowAutoApproved: true } },
  })
  assert.equal(outcome.outcome, "error")
  assert.match(outcome.outcome === "error" ? outcome.reason : "", /auto-approved/i)
  assert.equal(consumed, false)
})

test("v1 agent approval verifies the receipt and reserves the session before execution", async (t) => {
  const original = globalThis.fetch
  t.after(() => {
    globalThis.fetch = original
  })
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  const nonce = "agent-v1-test-nonce"
  const nbf = new Date().toISOString()
  const expiresAt = new Date(Date.now() + 180_000).toISOString()
  const liveConfig = {
    model: { provider: "test", version: "model-v1" },
    tools: [],
    systemPrompt: "Approve one payment",
  }
  const agentContext: AgentIntentContext = {
    action: { reversibility: "irreversible", amount: { amount: "10.00", currency: "SEK" } },
    agent: {
      label: "did:intyga:agent:payments",
      configDigest: agentConfigDigest(liveConfig),
      delegatedBy: null,
    },
    session: {
      id: `sha256:${"1".repeat(64)}`,
      seq: "1",
      prev: null,
      aggregate: { amount: "10.00", currency: "SEK" },
    },
    nbf,
  }
  const payload = canonicalIntentPayload({
    tenantId: SERVICE_TENANT,
    target: BASE.target,
    actionType: BASE.actionType,
    display: "Pay invoice",
    params: BASE.params,
    requester: { did: agentContext.agent.label, attestation: null },
    requirement: {
      requiredApprovals: 1,
      requireHardwareKey: false,
      allowedAaguids: [],
      requesterCannotApprove: true,
      signerClass: "human",
    },
    nonce,
    expiresAt,
    agentContext,
  })
  const receipt = {
    canonicalPayload: payload,
    actionDescription: "Pay invoice",
    params: BASE.params,
    requester: { did: agentContext.agent.label, attestation: null },
    signerDid: "did:intyga:owner",
    signerPublicKey: publicKey,
    signature: crypto
      .sign("sha256", Buffer.from(payload), {
        key: keys.privateKey,
        dsaEncoding: "ieee-p1363",
      })
      .toString("base64"),
    sigAlg: "ES256",
    verificationCode: "unused",
  }
  let seenInput: unknown
  let reserved = 0
  let config = liveConfig
  let driftOnConsume = false
  let reservationAllowed = true
  let abortOnReserve: AbortController | undefined
  const runtime: AgentV1Runtime = {
    tenantId: SERVICE_TENANT,
    requesterDid: agentContext.agent.label,
    approvers: {
      dids: ["did:intyga:owner"],
      resolveKey: (did: string) => (did === "did:intyga:owner" ? publicKey : null),
    },
    verifier: {},
    requirement: SERVICE_REQUIREMENT,
    prepare: async () => ({
      action: agentContext.action,
      delegatedBy: null,
      session: agentContext.session,
    }),
    liveConfig: async () => config,
    readState: async () => ({ head: null, seq: "0", aggregate: null }),
    reserve: async ({ next }) => {
      reserved++
      abortOnReserve?.abort(new Error("stopped after reservation"))
      return reservationAllowed && next.seq === "1"
    },
  }
  const json = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as Response
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    if (u.endsWith("/oauth/token")) return json({ access_token: "token" })
    if (u.endsWith("/authorize/verify")) {
      if (driftOnConsume) config = { ...liveConfig, systemPrompt: "Changed after approval" }
      return json({ ok: true })
    }
    if (u.endsWith("/authorize")) {
      seenInput = JSON.parse(String(init?.body))
      return json({ nonce, status: "PENDING", agentContext })
    }
    if (u.includes("/authorize/")) return json({ status: "APPROVED", receipt })
    throw new Error("unexpected endpoint")
  }) as typeof fetch

  const request = { ...BASE, actionDescription: "Pay invoice", executionTrust: undefined, agentV1: runtime }
  const approved = await requestApproval(request)
  assert.equal(approved.outcome, "approved", approved.outcome === "error" ? approved.reason : undefined)
  assert.equal(reserved, 1)
  assert.deepEqual((seenInput as { agentContext: unknown }).agentContext, {
    action: agentContext.action,
    delegatedBy: null,
    session: agentContext.session,
    configDigest: agentContext.agent.configDigest,
  })

  driftOnConsume = true
  const drifted = await requestApproval(request)
  assert.equal(drifted.outcome, "error")
  assert.match(drifted.outcome === "error" ? drifted.reason : "", /drifted/)
  assert.equal(reserved, 1)

  driftOnConsume = false
  config = liveConfig
  reservationAllowed = false
  const conflict = await requestApproval(request)
  assert.equal(conflict.outcome, "error")
  assert.match(conflict.outcome === "error" ? conflict.reason : "", /reservation refused/)
  assert.equal(reserved, 2)

  reservationAllowed = true
  abortOnReserve = new AbortController()
  const stopped = await requestApproval({ ...request, signal: abortOnReserve.signal })
  assert.equal(stopped.outcome, "error")
  assert.match(stopped.outcome === "error" ? stopped.reason : "", /stopped after reservation/)
  assert.equal(reserved, 3)
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

// ─── A 401 mid-wait is an expired token, not a blip ──────────────────────────
//
// The token is exchanged once per round trip and then used for the whole wait, and `timeoutMs` can
// exceed the token's TTL. Counting the resulting 401s as poll errors would abort a wait the human
// was about to finish, and would do it with a message blaming the gateway's availability.
test("a 401 mid-wait re-authenticates once and the redemption carries the new token", async (t) => {
  const gw = stubGateway([{ httpStatus: 401 }, { status: "APPROVED" }])
  t.after(gw.restore)

  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "approved")
  assert.equal(gw.exchanges(), 2, "exactly one re-exchange")
  assert.equal(gw.statusCalls(), 2, "the 401 is not a poll error and does not count toward the cutoff")
  // The token that was valid at the end of the wait is the one that must burn the approval.
  assert.equal(gw.consumeBearer(), "Bearer tok-2")
})

test("a second 401 after re-authenticating is an ordinary failure, not another exchange", async (t) => {
  // A revoked key answers 401 forever; one re-exchange is the allowance, then it counts like any
  // other failed check, so the wait ends at the cutoff instead of looping on the token endpoint.
  const gw = stubGateway([{ httpStatus: 401 }])
  t.after(gw.restore)

  const r = await requestApproval(BASE)
  assert.equal(r.outcome, "error")
  assert.match(r.outcome === "error" ? r.reason : "", /5 consecutive failures.*status check failed \(401\)/)
  assert.equal(gw.exchanges(), 2)
  assert.equal(gw.statusCalls(), 6, "one re-authenticated 401 plus the five that reach the cutoff")
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
    if (u.includes("/authorize/")) return json({ status: "APPROVED", receipt: serviceReceipt() })
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

test("a refused challenge surfaces the gateway's envelope, not [object Object]", async () => {
  // The gateway rewrites every non-2xx body into `{ error: { code, message, requestId } }`. Read as
  // `{ error?: string }` that reached the agent as the literal "[object Object]" and dropped the
  // requestId, which is the only way to find the matching gateway-side log line.
  const original = globalThis.fetch
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    if (u.endsWith("/oauth/token"))
      return { ok: true, status: 200, json: async () => ({ access_token: "tok" }) } as unknown as Response
    if (u.endsWith("/authorize"))
      return {
        ok: false,
        status: 402,
        json: async () => ({
          error: {
            code: "PAYMENT_REQUIRED",
            message: "Your plan does not permit this operation.",
            requestId: "req-abc",
          },
        }),
      } as unknown as Response
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  try {
    const r = await requestApproval(BASE)
    assert.equal(r.outcome, "error")
    const reason = r.outcome === "error" ? r.reason : ""
    assert.equal(reason.includes("[object Object]"), false)
    assert.match(reason, /PAYMENT_REQUIRED/)
    assert.match(reason, /Your plan does not permit this operation\./)
    assert.match(reason, /req-abc/)
  } finally {
    globalThis.fetch = original
  }
})

test("an unrecognised error body falls back to the authored message", async () => {
  const original = globalThis.fetch
  globalThis.fetch = (async (url: unknown) => {
    const u = String(url)
    if (u.endsWith("/oauth/token"))
      return { ok: true, status: 200, json: async () => ({ access_token: "tok" }) } as unknown as Response
    if (u.endsWith("/authorize"))
      return {
        ok: false,
        status: 502,
        json: async () => {
          throw new Error("not JSON")
        },
      } as unknown as Response
    throw new Error(`unexpected route: ${u}`)
  }) as typeof fetch

  try {
    const r = await requestApproval(BASE)
    assert.equal(r.outcome, "error")
    assert.match(r.outcome === "error" ? r.reason : "", /Failed to request approval challenge \(status 502\)/)
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
    if (u.includes("/authorize/")) return json({ status: "APPROVED", receipt: serviceReceipt() })
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

test("shutdown aborts a pending approval before polling or consumption", async (t) => {
  const original = globalThis.fetch
  t.after(() => {
    globalThis.fetch = original
  })
  const controller = new AbortController()
  let statusReads = 0
  let consumes = 0
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    const path = new URL(String(url)).pathname
    const json = (body: unknown) => Response.json(body)
    if (path === "/oauth/token") return json({ access_token: "tok" })
    if (path === "/authorize") {
      assert.equal(init?.signal?.aborted, false)
      controller.abort(new Error("proxy stopping"))
      return json({ nonce: "n-1" })
    }
    if (path === "/authorize/verify") consumes++
    else statusReads++
    return json({ status: "APPROVED", receipt: serviceReceipt(), ok: true })
  }) as typeof fetch
  const outcome = await requestApproval({ ...BASE, timeoutMs: 10_000, signal: controller.signal })
  assert.equal(outcome.outcome, "error")
  assert.match((outcome as { reason: string }).reason, /aborted|proxy stopping/i)
  assert.equal(statusReads, 0)
  assert.equal(consumes, 0)
})

test("shutdown between verdict and consume, or during consume, never returns approved", async (t) => {
  const original = globalThis.fetch
  t.after(() => {
    globalThis.fetch = original
  })
  for (const abortAt of ["verdict", "consume"] as const) {
    const controller = new AbortController()
    let consumes = 0
    globalThis.fetch = (async (url: unknown) => {
      const path = new URL(String(url)).pathname
      if (path === "/oauth/token") return Response.json({ access_token: "tok" })
      if (path === "/authorize") return Response.json({ nonce: "n-1" })
      if (path === "/authorize/verify") {
        consumes++
        if (abortAt === "consume") controller.abort(new Error("stopped during consume"))
        return Response.json({ ok: true })
      }
      if (abortAt === "verdict") controller.abort(new Error("stopped after verdict"))
      return Response.json({ status: "APPROVED", receipt: serviceReceipt() })
    }) as typeof fetch
    const outcome = await requestApproval({ ...BASE, signal: controller.signal })
    assert.equal(outcome.outcome, "error")
    assert.match((outcome as { reason: string }).reason, /stopped/)
    assert.equal(consumes, abortAt === "consume" ? 1 : 0)
  }
})

// ── Transport rules (@intyga/sdk transport.ts): https-only gateway, redirects never followed ──────

test("a plain-http, non-loopback gateway is refused before any request is sent", async () => {
  const original = globalThis.fetch
  let calls = 0
  globalThis.fetch = (async () => {
    calls++
    throw new Error("must not be called")
  }) as typeof fetch
  try {
    const r = await requestApproval({ ...BASE, gatewayUrl: "http://gw.example" })
    assert.equal(r.outcome, "error")
    assert.match((r as { reason: string }).reason, /gatewayUrl must use https:\/\//)
    assert.equal(calls, 0)
  } finally {
    globalThis.fetch = original
  }
})

/**
 * Two REAL local servers: `origin` plays the gateway and answers the paths in `redirect` with a 307
 * to the same path on `elsewhere`, which records anything that reaches it. A stub fetch could not
 * show this — the property is what undici does with a 307, not what the client asks it to do.
 */
async function redirectingGateway(
  t: { after: (fn: () => Promise<void>) => void },
  redirect: (path: string) => boolean,
) {
  const reached: string[] = []
  const listen = async (server: http.Server) => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    t.after(() => new Promise<void>((resolve) => server.close(() => resolve())))
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  }
  const elsewhere = await listen(
    http.createServer((req, res) => {
      let body = ""
      req.on("data", (c: Buffer) => {
        body += c.toString()
      })
      req.on("end", () => {
        reached.push(`${req.method} ${req.url} ${body}`)
        res.setHeader("content-type", "application/json")
        res.end(JSON.stringify({ access_token: "stolen", nonce: "n-1", status: "APPROVED", ok: true }))
      })
    }),
  )
  const origin = await listen(
    http.createServer((req, res) => {
      req.resume()
      const path = req.url ?? ""
      res.setHeader("content-type", "application/json")
      if (redirect(path)) {
        res.statusCode = 307
        res.setHeader("location", `${elsewhere}${path}`)
        res.end()
      } else if (path === "/oauth/token") res.end(JSON.stringify({ access_token: "tok" }))
      else if (path === "/authorize") res.end(JSON.stringify({ nonce: "n-1", status: "PENDING" }))
      else res.end(JSON.stringify({ status: "APPROVED", receipt: serviceReceipt() }))
    }),
  )
  return { origin, reached }
}

test("a 307 on the token exchange is not followed: the client secret never reaches the second origin", async (t) => {
  const { origin, reached } = await redirectingGateway(t, () => true)
  const r = await requestApproval({ ...BASE, gatewayUrl: origin })
  assert.equal(r.outcome, "error")
  assert.match((r as { reason: string }).reason, /status 307.*never follow redirects/)
  assert.deepEqual(reached, [])
})

test("a 307 on /authorize is not followed: the approval request never reaches the second origin", async (t) => {
  const { origin, reached } = await redirectingGateway(t, (p) => p === "/authorize")
  const r = await requestApproval({ ...BASE, gatewayUrl: origin })
  assert.equal(r.outcome, "error")
  assert.match((r as { reason: string }).reason, /Requesting the approval challenge failed \(status 307\)/)
  assert.deepEqual(reached, [])
})

test("a 307 on the status poll stops the wait at once instead of counting as a blip", async (t) => {
  const { origin, reached } = await redirectingGateway(t, (p) => p.startsWith("/authorize/n-1"))
  const r = await requestApproval({ ...BASE, gatewayUrl: origin, timeoutMs: 5_000 })
  assert.equal(r.outcome, "error")
  assert.match((r as { reason: string }).reason, /Approval status check failed \(status 307\)/)
  assert.deepEqual(reached, [])
})

test("a 307 on consume is not followed and the action does not run", async (t) => {
  const { origin, reached } = await redirectingGateway(t, (p) => p === "/authorize/verify")
  const r = await requestApproval({ ...BASE, gatewayUrl: origin })
  assert.equal(r.outcome, "error")
  assert.match((r as { reason: string }).reason, /Consuming the approved challenge failed \(status 307\)/)
  assert.deepEqual(reached, [])
})
