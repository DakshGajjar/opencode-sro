// Keep pyproject.toml's version equal to package.json's.
//
// This exists because `npm version` only knows about package.json. Without it,
// every single version bump leaves pyproject.toml behind, and the next publish
// fails in prepublishOnly on the version test — which is exactly what happened on
// 1.1.0, one release too late to be a good first impression of the tool.
//
// Wired into prepublishOnly rather than preversion, because preversion runs
// *before* the bump and cannot know the new number. Repairing after the fact and
// before the tests means `npm version X && npm publish` just works, and the test
// in tests/test_version.py stays the backstop for anyone running pytest directly.

import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, "..")

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"))
const target = join(root, "pyproject.toml")

const pyproject = readFileSync(target, "utf8")
const match = pyproject.match(/^version\s*=\s*"([^"]+)"/m)

if (!match) {
  console.error(`version:sync: no version line in ${target}`)
  process.exit(1)
}

if (match[1] === pkg.version) {
  console.log(`version:sync: pyproject.toml already at ${pkg.version}`)
  process.exit(0)
}

const updated = pyproject.replace(/^version\s*=\s*"[^"]+"/m, `version = "${pkg.version}"`)
writeFileSync(target, updated, "utf8")
console.log(`version:sync: pyproject.toml ${match[1]} -> ${pkg.version}`)