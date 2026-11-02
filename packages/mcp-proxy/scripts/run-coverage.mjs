import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { expectedBuiltModules, sha256File, unionBranchCoverage } from "./union-coverage.mjs"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const sourceNames = fs.readdirSync(path.join(root, "src"), { recursive: true }).map(String)
const builtNames = fs.readdirSync(path.join(root, "dist"), { recursive: true }).map(String)
const moduleNames = expectedBuiltModules(sourceNames, builtNames)
const distFiles = moduleNames.map((file) => path.join(root, "dist", file))
const before = new Map(distFiles.map((file) => [file, sha256File(file)]))
const raw = fs.mkdtempSync(path.join(os.tmpdir(), "intyga-proxy-coverage-"))
const tsx = path.resolve(root, "../../node_modules/.bin/tsx")
const run = spawnSync(
  tsx,
  [
    "--test",
    "--experimental-test-coverage",
    "--test-coverage-include=dist/**/*.js",
    "--test-coverage-lines=98",
    "--test-coverage-branches=0",
    "--test-coverage-functions=98",
    "src/**/*.test.ts",
  ],
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      NODE_V8_COVERAGE: raw,
      MCP_PROXY_TEST_CLI: path.join(root, "dist/cli.js"),
      MCP_PROXY_PROCESS_TREE_TEST_MODULE: path.join(root, "dist/process-tree.js"),
      MCP_PROXY_GATE_OPERATION_TEST_MODULE: path.join(root, "dist/gate-operation.js"),
    },
  },
)
if (run.status !== 0) process.exit(run.status ?? 1)
for (const [file, hash] of before) {
  if (sha256File(file) !== hash) throw new Error(`coverage build changed during execution: ${file}`)
}
const allowed = new Set(distFiles.map((file) => new URL(`file://${file}`).href))
const buildHash = [...before.values()].join(":")
const executions = fs
  .readdirSync(raw)
  .filter((file) => file.endsWith(".json"))
  .map((file) => {
    const parsed = JSON.parse(fs.readFileSync(path.join(raw, file), "utf8"))
    return { buildHash, result: parsed.result.filter((script) => allowed.has(script.url)) }
  })
  .filter((entry) => entry.result.length > 0)
const observed = new Set(executions.flatMap((entry) => entry.result.map((script) => script.url)))
const unloaded = [...allowed].filter((url) => !observed.has(url))
if (unloaded.length) {
  throw new Error(
    `coverage did not load every emitted production module: ${unloaded
      .map((url) => path.relative(root, fileURLToPath(url)))
      .join(", ")}`,
  )
}
const branch = unionBranchCoverage(executions)
console.log(`Union branch coverage: ${branch.percent.toFixed(2)}% (${branch.covered}/${branch.total})`)
for (const range of branch.uncovered) {
  const file = fileURLToPath(range.url)
  const source = fs.readFileSync(file, "utf8")
  const line = source.slice(0, range.startOffset).split("\n").length
  const snippet = source
    .slice(range.startOffset, Math.min(range.endOffset, range.startOffset + 100))
    .replace(/\s+/g, " ")
  console.log(
    `UNCOVERED ${path.basename(file)}:${line} ${range.functionName || "<top>"} ${JSON.stringify(snippet)}`,
  )
}
if (branch.percent < 98) process.exitCode = 1
