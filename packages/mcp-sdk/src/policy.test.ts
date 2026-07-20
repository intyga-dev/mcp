// The policy gate decides whether a tool call runs without a human. Every test here is really the
// same question asked from a different angle: can any input reach `allow` that shouldn't?

import assert from "node:assert/strict"
import { test } from "node:test"
import { evaluatePolicy } from "./policy.ts"

const policy = (rules: unknown) => JSON.stringify({ rules })
const local = (rules: unknown) => ({
  enforcement: "local-first" as const,
  localPolicyJson: policy(rules),
})

test("an explicitly allowed action runs without approval", () => {
  const ctx = local([{ action: "read_report", effect: "allow" }])
  assert.equal(evaluatePolicy("read_report", {}, ctx), "allow")
})

test("an explicitly denied action is blocked outright", () => {
  const ctx = local([{ action: "wipe_db", effect: "deny" }])
  assert.equal(evaluatePolicy("wipe_db", {}, ctx), "deny")
})

test("a rule with no effect escalates rather than assuming allow", () => {
  const ctx = local([{ action: "transfer" }])
  assert.equal(evaluatePolicy("transfer", {}, ctx), "require_approval")
})

test("an action absent from the policy escalates", () => {
  const ctx = local([{ action: "read_report", effect: "allow" }])
  assert.equal(evaluatePolicy("something_else", {}, ctx), "require_approval")
})

test("the first matching rule decides", () => {
  const ctx = local([
    { action: "transfer", effect: "deny" },
    { action: "transfer", effect: "allow" },
  ])
  assert.equal(evaluatePolicy("transfer", {}, ctx), "deny")
})

// ─── Fail-closed: nothing ambiguous may reach `allow` ────────────────────────

test("a malformed policy document escalates instead of failing open", () => {
  const ctx = { enforcement: "local-first" as const, localPolicyJson: "{not json" }
  assert.equal(evaluatePolicy("transfer", {}, ctx), "require_approval")
})

test("a policy with no rules array escalates", () => {
  const ctx = { enforcement: "local-first" as const, localPolicyJson: "{}" }
  assert.equal(evaluatePolicy("transfer", {}, ctx), "require_approval")
})

test("an absent policy escalates even under local-first", () => {
  assert.equal(evaluatePolicy("transfer", {}, { enforcement: "local-first" }), "require_approval")
})

test("gateway-enforced mode ignores any local allow and always escalates", () => {
  const ctx = {
    enforcement: "gateway-enforced" as const,
    localPolicyJson: policy([{ action: "transfer", effect: "allow" }]),
  }
  assert.equal(evaluatePolicy("transfer", {}, ctx), "require_approval")
})

test("an unset enforcement mode escalates", () => {
  assert.equal(
    evaluatePolicy("transfer", {}, { localPolicyJson: policy([{ action: "transfer", effect: "allow" }]) }),
    "require_approval",
  )
})

// ─── Spending ceilings ───────────────────────────────────────────────────────

const CEILING = local([{ action: "transfer", maxAmount: 100, effect: "allow" }])

test("a request under the ceiling is allowed", () => {
  assert.equal(evaluatePolicy("transfer", { amount: 99 }, CEILING), "allow")
})

test("a request exactly at the ceiling is allowed", () => {
  assert.equal(evaluatePolicy("transfer", { amount: 100 }, CEILING), "allow")
})

test("a request over the ceiling escalates to a human", () => {
  assert.equal(evaluatePolicy("transfer", { amount: 101 }, CEILING), "require_approval")
})

test("a deny rule with a ceiling still denies when exceeded", () => {
  const ctx = local([{ action: "transfer", maxAmount: 100, effect: "deny" }])
  assert.equal(evaluatePolicy("transfer", { amount: 500 }, ctx), "deny")
})

// These two are the reason the ceiling check was rewritten. Under the previous implementation the
// guard was `maxAmount !== undefined && handlerArgs.amount !== undefined`, so a caller who simply
// omitted `amount` skipped the comparison entirely and fell straight through to `allow` — an
// unbounded transfer for the price of dropping one field. A non-numeric amount did the same, since
// `NaN > 100` is false. A ceiling you cannot evaluate is not a ceiling that has been satisfied.
test("omitting the amount does not buy an unbounded allow", () => {
  assert.equal(evaluatePolicy("transfer", {}, CEILING), "require_approval")
})

test("a non-numeric amount does not slip past the ceiling", () => {
  // `[]`, `null`, `""` and `false` are the nasty ones: bare `Number()` turns every one of them into
  // 0, which sits under any ceiling and reads as a legitimate zero-value request.
  for (const amount of ["not-a-number", {}, [], Number.NaN, undefined, null, "", false, "  "]) {
    assert.equal(
      evaluatePolicy("transfer", { amount }, CEILING),
      "require_approval",
      `amount=${JSON.stringify(amount) ?? "undefined"} should escalate`,
    )
  }
})

test("a numeric string amount is still compared against the ceiling", () => {
  assert.equal(evaluatePolicy("transfer", { amount: "50" }, CEILING), "allow")
  assert.equal(evaluatePolicy("transfer", { amount: "5000" }, CEILING), "require_approval")
})

test("Infinity is treated as exceeding any ceiling", () => {
  assert.equal(evaluatePolicy("transfer", { amount: Number.POSITIVE_INFINITY }, CEILING), "require_approval")
})
