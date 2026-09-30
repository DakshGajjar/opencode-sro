#!/usr/bin/env node
/**
 * opencode-sro installer.
 *
 * Two jobs, because opencode cannot do them itself:
 *
 *   install-assets   copy agents/commands/instructions into ~/.config/opencode
 *                    and wire the instructions into opencode.json. The plugin
 *                    module cannot do this: opencode reads those from config
 *                    directories at startup, not from a plugin.
 *
 *   example          write a synthetic practice engagement to stdout, so a user
 *                    can exercise the whole thing without touching a real
 *                    program. Every asset uses the reserved .test TLD.
 *
 * Never overwrites a file the user has edited: if a same-named file is newer
 * than the one we ship, it is skipped and reported. --force overrides.
 */
import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises"
import { existsSync, readdirSync, statSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const HERE = path.dirname(fileURLToPath(import.meta.url))
// Sibling in a checkout (bin/ next to assets/) and in the tarball.
const ASSETS = ["..", "."]
  .map((rel) => path.join(HERE, rel, "assets"))
  .find((dir) => existsSync(dir))

const KINDS = ["agents", "commands", "instructions"]

function fail(message) {
  console.error(`sro: ${message}`)
  process.exit(1)
}

const HELP = [
  "opencode-sro",
  "",
  "  sro install-assets [--config-dir DIR] [--dry-run] [--force]",
  "      copy agents, commands and instructions into the opencode config dir",
  "",
  "  sro example",
  "      print a synthetic practice engagement to stdout",
  "",
].join("\n")

function parseFlags(argv) {
  const flags = { dryRun: false, force: false, configDir: null, command: null, help: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--dry-run") flags.dryRun = true
    else if (arg === "--force") flags.force = true
    else if (arg === "--config-dir") flags.configDir = argv[++i]
    else if (arg === "-h" || arg === "--help") flags.help = true
    else if (arg === "help") flags.command = "help"
    else if (!arg.startsWith("-") && !flags.command) flags.command = arg
  }
  if (!flags.configDir) {
    flags.configDir = path.join(homedir(), ".config", "opencode")
  } else {
    flags.configDir = path.resolve(flags.configDir)
  }
  return flags
}

function mdFilesIn(dir) {
  if (!existsSync(dir)) return []
  return readdirSync(dir).filter((name) => name.endsWith(".md")).sort()
}

async function installAssets(flags) {
  if (!ASSETS) fail("could not find assets/ next to the installer")
  console.log(`sro: installing assets into ${flags.configDir}`)
  if (flags.dryRun) console.log("sro: dry run, nothing will be written")

  let written = 0
  let skipped = 0

  for (const kind of KINDS) {
    const from = path.join(ASSETS, kind)
    const names = mdFilesIn(from)
    if (!names.length) continue
    const toDir = path.join(flags.configDir, kind)
    if (!flags.dryRun) await mkdir(toDir, { recursive: true })

    for (const name of names) {
      const target = path.join(toDir, name)
      const source = path.join(from, name)

      if (existsSync(target) && !flags.force) {
        const userIsNewer = statSync(target).mtimeMs >= statSync(source).mtimeMs
        if (userIsNewer) {
          console.log(`  skip   ${kind}/${name}  (yours is newer; --force to overwrite)`)
          skipped++
          continue
        }
      }
      if (!flags.dryRun) await cp(source, target)
      console.log(`  write  ${kind}/${name}`)
      written++
    }
  }

  // Wire the instructions in, or print the snippet to paste.
  const instructionPaths = KINDS.flatMap((kind) =>
    mdFilesIn(path.join(ASSETS, kind)).map((name) => `~/.config/opencode/${kind}/${name}`),
  )
  const configPath = path.join(flags.configDir, "opencode.json")

  if (existsSync(configPath)) {
    let config
    try {
      config = JSON.parse(await readFile(configPath, "utf8"))
    } catch (err) {
      fail(
        `${configPath} is not valid JSON (${err.message}).\n` +
          `       Add these to its "instructions" array by hand:\n` +
          instructionPaths.map((p) => `         "${p}"`).join(",\n"),
      )
      return
    }
    const existing = Array.isArray(config.instructions) ? config.instructions : []
    const merged = [...new Set([...existing, ...instructionPaths])]
    if (merged.length !== existing.length) {
      config.instructions = merged
      if (!flags.dryRun) await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf8")
      console.log(`  update opencode.json  (+${merged.length - existing.length} instructions)`)
    } else {
      console.log("  opencode.json  instructions[] already current")
    }
  } else {
    console.log(`\n  no ${configPath} yet. Add these to your opencode.json:\n`)
    console.log('    "instructions": [\n' + instructionPaths.map((p) => `      "${p}"`).join(",\n") + "\n    ]\n")
  }

  console.log(`\nsro: ${written} written, ${skipped} skipped. Restart opencode to load them.`)
  console.log("sro: to try it without touching a real program:")
  console.log("       mkdir -p ~/sro-playground && cd ~/sro-playground")
  console.log("       npx opencode-sro example > brief.json")
}

async function writeExample() {
  const source = path.join(HERE, "..", "examples", "practice-brief.json")
  if (!existsSync(source)) {
    fail("examples/practice-brief.json is missing from this install")
  }
  process.stdout.write(await readFile(source, "utf8"))
}

const flags = parseFlags(process.argv.slice(2))
const command = flags.command ?? "install-assets"

// Help is checked before anything else. Defaulting the command first meant
// `sro --help` fell through to install-assets and wrote files when someone only
// wanted to read the usage.
if (flags.help || command === "help") {
  console.log(HELP)
} else if (command === "install-assets") {
  await installAssets(flags)
} else if (command === "example") {
  await writeExample()
} else {
  fail(`unknown command ${command!r}. Try: install-assets, example\n\n${HELP}`)
}
