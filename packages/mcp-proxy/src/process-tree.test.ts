import assert from "node:assert/strict"
import { test } from "node:test"
import type { ChildProcess } from "node:child_process"
import type { ProcessTreeChild, ProcessTreeSystem } from "./process-tree.js"

const modulePath = process.env.MCP_PROXY_PROCESS_TREE_TEST_MODULE ?? "./process-tree.js"
const { nodeSystem, signalProcessTree } = (await import(modulePath)) as typeof import("./process-tree.js")

function fixture(overrides: Partial<ProcessTreeSystem> = {}, exited = false) {
  const events: string[] = []
  const task = { unref: () => events.push("unref") } as unknown as ChildProcess
  const child: ProcessTreeChild = {
    exitCode: exited ? 0 : null,
    signalCode: null,
    kill: (signal) => {
      events.push(`pid:${signal}`)
      return true
    },
  }
  const system: ProcessTreeSystem = {
    platform: "linux",
    kill: (pid, signal) => {
      events.push(`group:${pid}:${signal}`)
      return true
    },
    spawnTaskkill: (pid, force) => {
      events.push(`taskkill:${pid}:${force}`)
      return task
    },
    ...overrides,
  }
  return { child, events, system }
}

test("POSIX signals the process group and safely falls back while its leader is alive", () => {
  const normal = fixture()
  signalProcessTree(normal.child, 42, "SIGTERM", normal.system)
  assert.deepEqual(normal.events, ["group:-42:SIGTERM"])
  const raced = fixture({
    kill: () => {
      throw new Error("ESRCH")
    },
  })
  signalProcessTree(raced.child, 42, "SIGKILL", raced.system)
  assert.deepEqual(raced.events, ["pid:SIGKILL"])
})

test("Windows invokes and unreferences taskkill tree with force only for SIGKILL", () => {
  for (const [signal, force] of [
    ["SIGTERM", false],
    ["SIGKILL", true],
  ] as const) {
    const value = fixture({ platform: "win32" })
    signalProcessTree(value.child, 42, signal, value.system)
    assert.deepEqual(value.events, [`taskkill:42:${force}`, "unref"])
  }
})

test("an exited leader still signals its POSIX group without stale-PID fallback", () => {
  const descendants = fixture({}, true)
  signalProcessTree(descendants.child, 42, "SIGTERM", descendants.system)
  assert.deepEqual(descendants.events, ["group:-42:SIGTERM"])
  const gone = fixture(
    {
      kill: () => {
        throw new Error("ESRCH")
      },
    },
    true,
  )
  signalProcessTree(gone.child, 42, "SIGTERM", gone.system)
  assert.deepEqual(gone.events, [])
  signalProcessTree(gone.child, undefined, "SIGTERM", gone.system)
  assert.deepEqual(gone.events, [])
})

test("the shipped Node adapter invokes OS kill and constructs the Windows tree command", {
  skip: process.platform === "win32",
}, async () => {
  assert.throws(() => nodeSystem.kill(-2_000_000_000, "SIGTERM"))
  for (const force of [false, true]) {
    const task = nodeSystem.spawnTaskkill(42, force)
    const error = await new Promise<NodeJS.ErrnoException>((resolve) => task.once("error", resolve))
    assert.equal(error.code, "ENOENT")
  }
})
