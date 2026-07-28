// The local-first policy gate, shared by the in-process wrapper (`intygafyServer`) and the stdio proxy
// (@intyga/mcp-proxy). It used to be copy-pasted into both; a security decision that exists twice
// drifts, so it lives here once and is the only thing either caller consults.
//
// Fail-closed is the whole contract: every path that is not an explicit, matched `allow` must end at
// `require_approval` so a human is asked. Unknown action, absent policy, unparseable policy, wrong
// enforcement mode — all of them escalate rather than execute.

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
  if (ctx.enforcement !== "local-first" || !ctx.localPolicyJson) return "require_approval"

  let rules: PolicyRule[]
  try {
    rules = (JSON.parse(ctx.localPolicyJson) as PolicyManifest).rules ?? []
  } catch {
    // An unreadable policy is not permission to act.
    return "require_approval"
  }

  const rule = rules.find((r) => r.action === actionName)
  if (!rule) return "require_approval" // unknown action: ask a human

  const effect = rule.effect ?? "require_approval"

  if (rule.maxAmount !== undefined) {
    // A rule that states a ceiling only means "allow" while the request is *demonstrably* under it.
    // Anything we cannot read as a number fails the check rather than passing it — see toAmount for
    // why bare `Number()` is not safe here.
    const amount = toAmount(handlerArgs.amount)
    if (amount === undefined || amount > rule.maxAmount) {
      return effect === "allow" ? "require_approval" : effect
    }
  }

  return effect
}
