import { spawn, type ChildProcess } from "node:child_process"

export interface ProcessTreeChild {
  exitCode: number | null
  signalCode: NodeJS.Signals | null
  kill(signal: NodeJS.Signals): boolean
}
export interface ProcessTreeSystem {
  platform: NodeJS.Platform
  kill(pid: number, signal: NodeJS.Signals): boolean
  spawnTaskkill(pid: number, force: boolean): ChildProcess
}
export const nodeSystem: ProcessTreeSystem = {
  platform: process.platform,
  kill: (pid, signal) => process.kill(pid, signal),
  spawnTaskkill: (pid, force) =>
    spawn("taskkill", ["/pid", String(pid), "/t", ...(force ? ["/f"] : [])], {
      stdio: "ignore",
      windowsHide: true,
    }),
}

/** Signal a wrapped launcher's whole tree, including descendants after the launcher exits. */
export function signalProcessTree(
  child: ProcessTreeChild,
  pid: number | undefined,
  signal: NodeJS.Signals,
  system: ProcessTreeSystem = nodeSystem,
): void {
  if (pid === undefined) return
  if (system.platform === "win32") {
    system.spawnTaskkill(pid, signal === "SIGKILL").unref()
    return
  }
  try {
    system.kill(-pid, signal)
  } catch {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal)
  }
}
