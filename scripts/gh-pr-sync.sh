#!/usr/bin/env bash
# Sync the opencode-sro entry's PR body with what the package actually is now.
#
# Why this exists instead of a one-line `gh pr edit --body`: the body was written
# against 0.2.0 and now contradicts 1.0.0 in three places. It says "no generic
# HTTP tool" (there is now `dns_resolve`), "11 commands" (there are 16) and "480
# tests" (there are 726). Appending a 1.0.0 section under those claims produces a
# PR that contradicts itself, which is the same defect this repo has spent the
# whole session fixing in its own documentation.
#
# So it does two things, and both are idempotent:
#   1. corrects the stale lines, in place
#   2. appends a marked 1.0.0 section, if the marker is absent
#
# Re-run it as often as you like; a second run changes nothing and prints
# "already current". It never clobbers: it reads the live body, transforms that,
# and writes it back. If the read comes back empty it stops rather than replacing
# a real description with a stub.
#
# Usage:
#   scripts/gh-pr-sync.sh                       # edit the existing PR
#   scripts/gh-pr-sync.sh --create              # create it if there is none
#   scripts/gh-pr-sync.sh --repo owner/name     # different repo
#   scripts/gh-pr-sync.sh --dry-run             # print the diff, write nothing

set -euo pipefail

REPO="${SRO_PR_REPO:-awesome-opencode/awesome-opencode}"
HEAD_BRANCH="${SRO_PR_HEAD:-add-opencode-sro}"
MARKER='<!-- sro:release -->'
DRY_RUN=0
CREATE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --branch) HEAD_BRANCH="$2"; shift 2 ;;
    --create) CREATE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is not installed" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || {
  echo "gh is not authenticated. Run: gh auth login --hostname github.com --git-protocol https --web" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BODY="$WORK/body.md"

# --- locate the PR --------------------------------------------------------

PR_NUMBER="$(gh pr list --repo "$REPO" --head "$HEAD_BRANCH" --state all \
  --json number --jq '.[0].number // empty' 2>/dev/null || true)"

if [ -z "$PR_NUMBER" ]; then
  if [ "$CREATE" -eq 0 ]; then
    echo "no PR found for $HEAD_BRANCH in $REPO." >&2
    echo "Pass --create to open one from pr-body.md." >&2
    exit 1
  fi
  PR_NUMBER=""
  echo "no existing PR; will create one for $HEAD_BRANCH"
else
  echo "found PR #$PR_NUMBER in $REPO (head $HEAD_BRANCH)"
fi

# --- read the live body ---------------------------------------------------

if [ -n "$PR_NUMBER" ]; then
  gh pr view "$PR_NUMBER" --repo "$REPO" --json body --jq '.body // ""' > "$BODY"
  # A body that is empty or whitespace means something went wrong upstream. Writing
  # our transform over it would replace a real description with a stub, which is
  # strictly worse than doing nothing.
  if [ ! -s "$BODY" ] || [ -z "$(tr -d '[:space:]' < "$BODY")" ]; then
    echo "PR #$PR_NUMBER has an empty body; refusing to overwrite it." >&2
    exit 1
  fi
else
  cp "$(dirname "$0")/../pr-body.md" "$BODY"
  [ -s "$BODY" ] || { echo "pr-body.md is empty" >&2; exit 1; }
fi

# --- transform ------------------------------------------------------------

cat > "$WORK/section.md" <<'SECTION'

<!-- sro:release -->
## 1.0.0

The first release where the control plane, the documentation and the code agree
with each other.

**What works now:** 6 of 14 catalog tools, five local and read-only plus
`dns_resolve`. The other eight are declared with `implemented: false` and return a
refusal naming the tools that do work. `sro_capabilities` reports which is which,
so the catalog is not a promise list.

`dns_resolve` is the only tool that touches a network. It resolves names and
classifies every address they return — `public`, `private`, `loopback`,
`link-local`, `metadata` — so a hostname that resolves inward shows up as a
result rather than a silent nothing. It cannot connect to anything.

**The egress layer** (`sro/core/egress.py`) is the only component allowed to open
a socket. A handler receives a session already bound to an approved target and
cannot name a different one. It resolves once, refuses private and metadata
ranges, and connects to the pinned address — so the window between "we decided
this was allowed" and "we connected" does not exist. Limits are frozen and
`send()` takes no overrides. Response bodies pass through the same untrusted fence
as program text, with the target named as provenance, because a response body is
attacker-controlled text arriving in a context trusted to follow instructions.

**Documentation that cannot drift.** `METHOD.md` and `docs/EGRESS.md` ship with
the package and are checked against the implementation by the test suite: every
tool named in the method must be implemented rather than merely declared, every
network tool must have a verdict in the review, and "nothing is approved" is
asserted so the suite fails the day a second network tool ships.

**A scope bypass was found and fixed on the way.** `target=api.acme.test` with
`url=https://admin.acme.test/secret` returned `ALLOW`: the policy ladder resolved
the supplied target and ignored the URL, which is what would actually have been
fetched. It was invisible while every network tool was unimplemented and would
have gone live with the first one.

**Shipped surface:** 10 agents, 16 commands, 6 instruction files, 726 tests.
Standard library only at runtime — no Python dependencies, and one npm dependency
that is the plugin SDK.
SECTION

python3 - "$BODY" "$WORK/section.md" "$MARKER" <<'PY'
import pathlib
import sys

body_path, section_path, marker = sys.argv[1], sys.argv[2], sys.argv[3]
text = pathlib.Path(body_path).read_text(encoding="utf-8")
section = pathlib.Path(section_path).read_text(encoding="utf-8").rstrip("\n")

# (old, new) — each is a claim that 1.0.0 made false. Ordered so the longer,
# more specific phrase wins over the shorter one containing it.
CORRECTIONS = [
    (
        "- **Tool broker** — a closed catalog. No shell access, no generic HTTP tool.",
        "- **Tool broker** — a closed catalog of 14 declared tools, 6 implemented. No shell "
        "access. The one network tool is `dns_resolve`, and it cannot connect to anything; "
        "everything that would reach a third party's system is declared, refused, and says why.",
    ),
    (
        "10 agents, 11 commands, 5 instruction files, 480 tests. Standard library only at runtime.",
        "10 agents, 16 commands, 6 instruction files, 726 tests. Standard library only at "
        "runtime — no Python dependencies.",
    ),
    (
        "- **Local-first routing** — sensitive material routes local, external inference off by default.",
        "- **Local-first routing** — sensitive material routes local, external inference off by default.\n"
        "- **Egress transport** — one reviewed component holds every network control, so a "
        "handler cannot become a second implementation of it.",
    ),
]

applied = []
for old, new in CORRECTIONS:
    if new in text:
        continue  # already corrected
    if old in text:
        text = text.replace(old, new, 1)
        applied.append(old.split("—")[0].strip("- ").strip())

if marker in text:
    print("  release section: already present")
else:
    text = text.rstrip("\n") + "\n" + section + "\n"
    applied.append("release section")

pathlib.Path(body_path).write_text(text, encoding="utf-8")

if applied:
    print("  applied:")
    for item in applied:
        print(f"    - {item}")
else:
    print("  already current; nothing to change")
PY

# --- write back -----------------------------------------------------------

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  echo "--- dry run: body would change as follows ---"
  gh pr view "$PR_NUMBER" --repo "$REPO" --json body --jq '.body' 2>/dev/null > "$WORK/old.md" || true
  diff -u "$WORK/old.md" "$BODY" || true
  exit 0
fi

if [ -n "$PR_NUMBER" ]; then
  gh pr edit "$PR_NUMBER" --repo "$REPO" --body-file "$BODY"
  echo "updated PR #$PR_NUMBER"
  gh pr view "$PR_NUMBER" --repo "$REPO" --json url --jq '.url'
else
  gh pr create --repo "$REPO" --base main --head "$HEAD_BRANCH" \
    --title "add: SRO (Security Research Orchestrator) to plugins" \
    --body-file "$BODY"
fi
