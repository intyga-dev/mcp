import fs from "node:fs"
import crypto from "node:crypto"

export const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")

/** Match every production TypeScript module to exactly one emitted JavaScript module. */
export function expectedBuiltModules(sourceFiles, builtFiles) {
  const expected = sourceFiles
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts"))
    .map((file) => `${file.slice(0, -3)}.js`)
    .sort()
  const actual = builtFiles.filter((file) => file.endsWith(".js")).sort()
  const missing = expected.filter((file) => !actual.includes(file))
  const unexpected = actual.filter((file) => !expected.includes(file))
  if (missing.length || unexpected.length) {
    throw new Error(
      `coverage module mismatch: missing=[${missing.join(", ")}] unexpected=[${unexpected.join(", ")}]`,
    )
  }
  return expected
}

function countAt(ranges, offset) {
  let selected
  for (const range of ranges) {
    if (range.startOffset <= offset && offset < range.endOffset) {
      if (!selected || range.endOffset - range.startOffset < selected.endOffset - selected.startOffset)
        selected = range
    }
  }
  return selected?.count ?? 0
}

/** Union V8 block ranges from separate executions of one byte-identical build. */
export function unionBranchCoverage(executions) {
  const builds = new Set(executions.map((entry) => entry.buildHash))
  if (builds.size !== 1) throw new Error("refusing to merge coverage from different builds")
  const functions = new Map()
  for (const execution of executions) {
    for (const script of execution.result) {
      for (const fn of script.functions) {
        const root = fn.ranges[0]
        if (!root) continue
        const key = `${script.url}\0${fn.functionName}\0${root.startOffset}\0${root.endOffset}`
        const item = functions.get(key) ?? {
          url: script.url,
          functionName: fn.functionName,
          runs: [],
          branches: new Map(),
        }
        item.runs.push(fn.ranges)
        for (const range of fn.ranges.slice(1))
          item.branches.set(`${range.startOffset}:${range.endOffset}`, range)
        functions.set(key, item)
      }
    }
  }
  let covered = 0
  let total = 0
  const uncovered = []
  for (const item of functions.values()) {
    for (const range of item.branches.values()) {
      total++
      const midpoint = range.startOffset + Math.floor((range.endOffset - range.startOffset - 1) / 2)
      if (item.runs.some((ranges) => countAt(ranges, midpoint) > 0)) covered++
      else uncovered.push({ url: item.url, functionName: item.functionName, ...range })
    }
  }
  return { covered, total, percent: total === 0 ? 100 : (covered / total) * 100, uncovered }
}
