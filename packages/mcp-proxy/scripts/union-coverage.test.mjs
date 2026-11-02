import assert from "node:assert/strict"
import { test } from "node:test"
import { expectedBuiltModules, unionBranchCoverage } from "./union-coverage.mjs"

const execution = (buildHash, left, right) => ({
  buildHash,
  result: [
    {
      url: "file:///dist/cli.js",
      functions: [
        {
          functionName: "f",
          ranges: [
            { startOffset: 0, endOffset: 100, count: 1 },
            { startOffset: 10, endOffset: 20, count: left },
            { startOffset: 30, endOffset: 40, count: right },
          ],
        },
      ],
    },
  ],
})

test("complementary child executions union identical block offsets", () => {
  const result = unionBranchCoverage([execution("same", 1, 0), execution("same", 0, 1)])
  assert.deepEqual(
    { covered: result.covered, total: result.total, percent: result.percent },
    {
      covered: 2,
      total: 2,
      percent: 100,
    },
  )
})

test("a loaded but never executed block still fails the union", () => {
  assert.equal(unionBranchCoverage([execution("same", 1, 0)]).percent, 50)
})

test("coverage from different builds is never merged", () => {
  assert.throws(
    () => unionBranchCoverage([execution("old", 1, 0), execution("new", 0, 1)]),
    /different builds/,
  )
})

test("production source and emitted coverage modules must correspond exhaustively", () => {
  assert.deepEqual(
    expectedBuiltModules(["cli.ts", "cli.test.ts", "nested/helper.ts"], ["cli.js", "nested/helper.js"]),
    ["cli.js", "nested/helper.js"],
  )
  assert.throws(
    () => expectedBuiltModules(["cli.ts", "new-module.ts"], ["cli.js"]),
    /missing=\[new-module\.js\]/,
  )
  assert.throws(() => expectedBuiltModules(["cli.ts"], ["cli.js", "stale.js"]), /unexpected=\[stale\.js\]/)
})
