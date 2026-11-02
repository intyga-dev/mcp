export type GateOperationResult = { ok: true } | { ok: false; error: unknown }

/** Run one gate operation and return an explicit fail-closed outcome for unexpected failures. */
export async function runGateOperation(run: () => Promise<void>): Promise<GateOperationResult> {
  try {
    await run()
    return { ok: true }
  } catch (error) {
    return { ok: false, error }
  }
}
