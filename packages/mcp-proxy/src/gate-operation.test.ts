import assert from "node:assert/strict"
import { test } from "node:test"

const modulePath = process.env.MCP_PROXY_GATE_OPERATION_TEST_MODULE ?? "./gate-operation.js"
const { runGateOperation } = (await import(modulePath)) as typeof import("./gate-operation.js")

test("unexpected gate dependency failures are refused without escaping", async () => {
  const privateFailure = new Error("private provider detail")
  const result = await runGateOperation(async () => {
    throw privateFailure
  })
  assert.deepEqual(result, { ok: false, error: privateFailure })
})

test("successful gate operations do not emit a refusal", async () => {
  let ran = false
  const result = await runGateOperation(async () => {
    ran = true
  })
  assert.equal(ran, true)
  assert.deepEqual(result, { ok: true })
})
