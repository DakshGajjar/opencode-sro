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
import { existsSync, readdirSync } from "node:fs"
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
        // Compare content, not mtime. An mtime rule gets this wrong in the
        // dangerous direction: a user edits a file, a new SRO version ships
        // with a newer mtime, and the edit is silently destroyed. Content is
        // the only reliable signal that the file is ours or theirs.
        const installed = await readFile(target, "utf8")
        const shipped = await readFile(source, "utf8")
        if (installed === shipped) {
          console.log(`  same   ${kind}/${name}`)
          continue
        }
        console.log(`  KEEP   ${kind}/${name}  (differs from ours; --force to overwrite)`)
        skipped++
        continue
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
  // opencode.jsonc is the filename most installs actually use. Looking only for
  // opencode.json meant a jsonc user got the assets copied and the instructions
  // silently never wired, with a message about a file they do not have.
  const jsonPath = path.join(flags.configDir, "opencode.json")
  const jsoncPath = path.join(flags.configDir, "opencode.jsonc")
  const configPath = existsSync(jsonPath) ? jsonPath : existsSync(jsoncPath) ? jsoncPath : null

  if (configPath && configPath.endsWith(".jsonc")) {
    // Rewriting a jsonc file as JSON would discard every comment in it, and a
    // config file is mostly comments. Print the snippet instead of silently
    // destroying them.
    console.log(`\n  ${configPath} found (jsonc). Add these to its "instructions" array:`)
    console.log(
      '    "instructions": [\n' + instructionPaths.map((p) => `      "${p}"`).join(",\n") + "\n    ]\n",
    )
    console.log("  (not editing it: rewriting jsonc as JSON would drop your comments)")
  } else if (configPath) {
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
    console.log(`\n  no opencode.json or opencode.jsonc in ${flags.configDir}. Add these to it:\n`)
    console.log('    "instructions": [\n' + instructionPaths.map((p) => `      "${p}"`).join(",\n") + "\n    ]\n")
  }

  // In a dry run the counter describes what would happen. Saying "written" for
  // files that were not written makes the one mode whose whole purpose is
  // inspection the one mode that overstates what it did.
  const verb = flags.dryRun ? "would write" : "written"
  console.log(`\nsro: ${written} ${verb}, ${skipped} skipped.${flags.dryRun ? "" : " Restart opencode to load them."}`)
  console.log("sro: to try it without touching a real program, run opencode from")
  console.log("     the directory you installed into (not a subdirectory, or the")
  console.log("     plugin will not resolve):")
  console.log("       npx opencode-sro example > brief.json")
  console.log("       opencode")
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
  fail(`unknown command ${String(command)}. Try: install-assets, example\n\n${HELP}`)
}
