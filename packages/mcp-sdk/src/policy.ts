// The local-first policy gate, shared by the in-process wrapper (`intygafyServer`) and the stdio proxy
// (@intyga/mcp-proxy). It used to be copy-pasted into both; a security decision that exists twice
// drifts, so it lives here once and is the only thing either caller consults.
//
// Fail-closed is the whole contract: every path that is not an explicit, matched `allow` must end at
// `require_approval` so a human is asked. Unknown action, absent policy, unparseable policy, wrong
// enforcement mode — all of them escalate rather than execute.

import { z } from "zod"

export type PolicyDecision = "allow" | "deny" | "require_approval"

export interface PolicyRule {
  action: string
  maxAmount?: number
  effect?: PolicyDecision
}

export interface PolicyManifest {
  rules?: PolicyRule[]
}

export interface PolicyContext {
  enforcement?: "local-first" | "gateway-enforced"
  localPolicyJson?: string
}

// The policy document is an untrusted boundary — an operator's hand-written file, or something a
// deployment tool generated. Parsing it by cast (`as PolicyManifest`) is what let three
// parseable-but-wrong shapes throw out of this function instead of escalating: `{"rules":{}}` and
// `{"rules":5}` both died on `.find`, and `{"rules":[null]}` died reading `.action` off null.
//
// One malformed rule fails the whole document rather than being skipped. That is deliberate: a
// policy the operator cannot have meant is not a policy to partially honour, and escalating every
// action to a human is the safe reading of "I don't understand this file".
const policyDecisionSchema = z.enum(["allow", "deny", "require_approval"])

const policyRuleSchema = z.object({
  action: z.string(),
  // A ceiling that isn't a finite number is not a ceiling. `maxAmount: "abc"` used to make
  // `amount > rule.maxAmount` a NaN comparison — false — which skipped the guard and returned
  // `allow`, turning a typo into an unbounded auto-approve.
  maxAmount: z
    .number()
    .refine((n) => Number.isFinite(n))
    .optional(),
  // Anything outside the three literals (`"ALLOW"`, `"permit"`, a number) is not a decision we can
  // act on. Previously it was returned verbatim, typed as `PolicyDecision` but not being one.
  effect: policyDecisionSchema.optional(),
})

const policyManifestSchema = z.object({
  rules: z.array(policyRuleSchema).optional(),
})

/**
 * Read a spend amount, or `undefined` if the value isn't one. Deliberately stricter than `Number()`:
 * JS coerces `[]`, `null`, `""` and `false` all to 0, which would sail under any ceiling and turn a
 * junk field into an unbounded allow. Only real numbers and numeric strings count.
 */
function toAmount(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined
  if (typeof value !== "string" || value.trim() === "") return undefined
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}

/**
 * Decide what to do with a tool call before it executes. Pure — no I/O, no clock, no network — so it
 * is exhaustively testable and identical on both call paths.
 *
 * Only `enforcement: "local-first"` with a parseable policy can produce anything other than
 * `require_approval`; under `gateway-enforced` the gateway is the authority and every call escalates.
 */
export function evaluatePolicy(
  actionName: string,
  handlerArgs: Record<string, unknown>,
  ctx: PolicyContext,
): PolicyDecision {
  // Total by construction. Callers treat a thrown error very differently from a returned verdict —
  // @intyga/mcp-proxy used to forward the tool call to the child on any throw — so the contract is
  // that this function returns a decision for every input, including ones a future edit gets wrong.
  try {
    return decide(actionName, handlerArgs, ctx)
  } catch {
    return "require_approval"
  }
}

function decide(
  actionName: string,
  handlerArgs: Record<string, unknown>,
  ctx: PolicyContext,
): PolicyDecision {
  if (ctx.enforcement !== "local-first" || !ctx.localPolicyJson) return "require_approval"

  let document: unknown
  try {
    document = JSON.parse(ctx.localPolicyJson)
  } catch {
    // An unreadable policy is not permission to act.
    return "require_approval"
  }

  const manifest = policyManifestSchema.safeParse(document)
  // Parseable JSON in a shape we don't recognise is no better than unparseable JSON.
  if (!manifest.success) return "require_approval"

  const rules = manifest.data.rules ?? []

  const rule = rules.find((r) => r.action === actionName)
  if (!rule) return "require_approval" // unknown action: ask a human

  const effect = rule.effect ?? "require_approval"

  if (rule.maxAmount !== undefined) {
    // A rule that states a ceiling only means "allow" while the request is *demonstrably* under it.
    // Anything we cannot read as a number fails the check rather than passing it — see toAmount for
    // why bare `Number()` is not safe here. The ceiling itself is validated at parse time, so this
    // comparison can no longer be NaN on the right-hand side either.
    const amount = toAmount(handlerArgs.amount)
    if (amount === undefined || amount > rule.maxAmount) {
      return effect === "allow" ? "require_approval" : effect
    }
  }

  return effect
}
