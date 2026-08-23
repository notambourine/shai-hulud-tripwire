#!/usr/bin/env bash
#
# Supply-chain tripwire — fail CI on known Shai-Hulud / Mini Shai-Hulud IOCs.
#
# Threat model: a compromised npm dependency (or a force-pushed branch) plants
# persistence artifacts — a malicious GitHub Actions workflow that dumps
# `toJSON(secrets)`, a `preinstall`/`prepare` lifecycle hook, or a dead-drop
# payload file — and waits for your runner to execute it with deploy tokens,
# cloud keys, npm tokens, and GITHUB_TOKEN in scope. This script does a pure
# git-tree scan (no `npm/pnpm install`, no network, no secrets) of the current
# working tree, so it is safe to run as the FIRST job in a pipeline, before any
# job that holds a secret. If it finds an IOC it exits non-zero.
#
# IOC sources (2025-09 -> 2026-08 campaigns):
#   - Checkmarx: "Shai-Hulud 1.0" (2025-09), the shai-hulud-workflow.yml dropper
#   - Microsoft Security: "Shai-Hulud 2.0" (2025-12-09)
#   - StepSecurity: node-ipc 9.1.6/9.2.3/12.0.1 credential stealer (2026-05)
#   - Phoenix Security: "TrapDoor" hidden-Unicode agent-config poisoning (2026-05)
#   - StepSecurity / Snyk / Sophos: "Mini Shai-Hulud" (2026-05)
#   - Socket.dev: "Mini Shai-Hulud / Miasma / Hades" PyPI + MCP wave (2026-06)
#   - Elastic / Microsoft / JFrog: "ChainDrop" keyv wave, on-chain C2 (2026-08)
#   - Unit 42 / CISA npm supply-chain advisories
#
# This catches the PERSISTENCE layer (workflows, dead-drop files, exfil
# domains). Package-level detection is best handled separately — e.g. Socket
# Firewall on the install step, and a package-manager build-script allowlist
# (pnpm `onlyBuiltDependencies`, or `npm ci --ignore-scripts`).
#
# Run locally:  bash scripts/supply-chain-tripwire.sh
set -euo pipefail

# --- file set -------------------------------------------------------------
# Scan only git-tracked files in the CURRENT working tree (the caller's repo
# when run from a GitHub Action). Avoids node_modules/build-output noise and
# means a force-pushed payload (which must be committed to run in CI) is in
# scope. Read loop (not `mapfile`) so this runs on macOS's Bash 3.2 as well as
# CI's Bash 5.
TRACKED=()
while IFS= read -r _f; do TRACKED+=("$_f"); done < <(git ls-files)

# --- content-scan allowlist -----------------------------------------------
# The content greps below reference IOC literals, so any file that legitimately
# DOCUMENTS those IOCs (this scanner, a security README) must be exempt from
# content scanning or it would match itself. The scanner script is always
# allowed. Repos that document IOCs can add more globs via $TRIPWIRE_ALLOW
# (newline- or space-separated). Filename, hash, and lifecycle-script checks
# are NOT subject to the allowlist.
ALLOW_GLOBS=( "*supply-chain-tripwire.sh" )
if [[ -n "${TRIPWIRE_ALLOW:-}" ]]; then
  while IFS=$' \t\n' read -r _g; do
    [[ -n "$_g" ]] && ALLOW_GLOBS+=("$_g")
  done <<< "${TRIPWIRE_ALLOW//[$' \t']/$'\n'}"
fi
is_allowed() {
  local f="$1" g
  for g in "${ALLOW_GLOBS[@]}"; do
    # shellcheck disable=SC2053  # intentional glob match, not literal compare
    [[ "$f" == $g ]] && return 0
  done
  return 1
}

HITS=()
hit() { HITS+=("$1"); }

# --- 1. dead-drop / payload filenames -------------------------------------
# Exact basenames the worm writes to disk. Matched by NAME, so this script
# naming them as data never self-trips.
BAD_BASENAMES=(
  "router_init.js"          # Mini Shai-Hulud — embedded in @tanstack pkgs
  "tanstack_runner.js"      # Mini Shai-Hulud — git-fetched payload
  "setup_bun.js"            # Shai-Hulud 2.0 — installs Bun runtime
  "bun_environment.js"      # Shai-Hulud 2.0 — credential gather + exfil
  "set_bun.js"              # Shai-Hulud 2.0 — preinstall dropper
  "gh-token-monitor.sh"     # Mini Shai-Hulud — token-stealing daemon
  "router_runtime.js"       # Mini Shai-Hulud — Bun payload copy
  "langchain_core-setup.pth" # Miasma/Hades — Python startup-hook dropper (PyPI wave)
  "ensmallen_haswell.abi3.so" # Miasma/Hades — native import-time payload
  "ensmallen_core2.abi3.so"  # Miasma/Hades — native import-time payload
)
# NB: the worm's run-once marker (/<tmp>/.bun_ran) and SSH-propagation file
# (/tmp/.sshu-setup.js) are written to system temp at RUNTIME, never committed —
# a git-tree scan can't see them. They're caught by the .pth/marker checks on the
# code that drops them, not by basename here. Listed for the record, not scanned.
for f in "${TRACKED[@]}"; do
  base="${f##*/}"
  for bad in "${BAD_BASENAMES[@]}"; do
    [[ "$base" == "$bad" ]] && hit "dead-drop payload file: $f"
  done
done

# Persistence drop locations (agent/editor hooks the worm hijacks).
for f in "${TRACKED[@]}"; do
  case "$f" in
    .claude/setup.mjs|.vscode/setup.mjs|.claude/router_runtime.js) \
      hit "agent/editor persistence hook: $f" ;;
  esac
done

# --- 2. malicious GitHub Actions workflow behavior ------------------------
# The worm's persistence workflow dumps every secret. `toJSON(secrets)` has no
# legitimate use — real workflows reference named secrets only.
for f in "${TRACKED[@]}"; do
  is_allowed "$f" && continue
  case "$f" in .github/workflows/*) ;; *) continue ;; esac
  if grep -Eq 'toJSON\(\s*secrets\s*\)' "$f"; then
    hit "workflow dumps all secrets (toJSON(secrets)): $f"
  fi
done

# Shai-Hulud 1.0's dropper workflow. Checkmarx published the NAME only, so the
# content grep above cannot see it and the basename is the whole IOC.
for f in "${TRACKED[@]}"; do
  case "${f##*/}" in
    shai-hulud-workflow.yml|shai-hulud-workflow.yaml) \
      hit "known campaign dropper workflow: $f" ;;
  esac
done

# --- 2b. Python .pth startup-hook persistence -----------------------------
# A .pth file in site-packages executes any line beginning with `import` at
# interpreter startup. The Miasma/Hades PyPI wave plants `langchain_core-setup.pth`
# carrying an `import ...; <exec>` one-liner so its payload runs on every `python`
# invocation — a Python analogue of the agent/editor hooks above. Legit .pth files
# only list directory paths; an `import`-line .pth carrying an exec sink in a SOURCE
# tree is the anomaly. Content-based, so allowlistable (a repo may vendor a real one).
PTH_EXEC_RE='^[[:space:]]*import[[:space:]].*(exec|eval|compile|os\.|subprocess|__import__|importlib|base64|urllib|socket)'
for f in "${TRACKED[@]}"; do
  is_allowed "$f" && continue
  case "$f" in *.pth) ;; *) continue ;; esac
  if grep -EqI "$PTH_EXEC_RE" "$f"; then
    hit "Python .pth startup-hook executes code at interpreter startup: $f"
  fi
done

# --- 2c. hidden Unicode in agent-instruction files ------------------------
# TrapDoor (2026-05) hides instructions the agent tokenizes and the reviewer cannot see.

# Escaped BYTES, never literal codepoints: a signature you cannot see in the file
# defining it is one nobody can review. LC_ALL=C keeps [[:print:]] at ASCII 0x20-0x7e.
ZW_BYTES='\xe2\x80\x8b|[[:print:]]\xe2\x80\x8c|\xe2\x80\x8c[[:print:]]'
# Only U+200B is unconditional; a printable ASCII neighbour is what separates a
# smuggled codepoint from emoji ZWJ, a leading BOM, and Persian/Urdu U+200C prose.
ZW_BYTES="$ZW_BYTES"'|[[:print:]]\xe2\x81\xa0|\xe2\x81\xa0[[:print:]]'
ZW_BYTES="$ZW_BYTES"'|[[:print:]]\xe2\x80\x8d|\xe2\x80\x8d[[:print:]]|[[:print:]]\xef\xbb\xbf'
# Unicode Tag block (U+E0000-E007F), the ASCII-smuggling vector: leading form only,
# so an emoji subdivision flag, whose tags follow a non-ASCII base, stays exempt.
ZW_BYTES="$ZW_BYTES"'|[[:print:]]\xf3\xa0[\x80\x81]'
ZW_RE=$(printf '%b' "$ZW_BYTES")

# Prose configs get the zero-width test ONLY, never the greps above: a CLAUDE.md
# documenting `curl ... | sh` is a README, a settings.json running one is wiring.
is_agent_config() {
  case "${1##*/}" in CLAUDE.md|AGENTS.md|.cursorrules|copilot-instructions.md) return 0 ;; esac
  # Nested too: a monorepo carries a .claude/ per workspace, not just at the root.
  case "$1" in .claude/*|.cursor/*|*/.claude/*|*/.cursor/*) return 0 ;; esac
  return 1
}
for f in "${TRACKED[@]}"; do
  is_allowed "$f" && continue
  is_agent_config "$f" || continue
  # -I, not -a: a committed binary asset under .claude/ would otherwise hard-fail
  # the caller's pipeline on a 1-in-8-per-2MB chance of these three bytes.
  if LC_ALL=C grep -qIE "$ZW_RE" "$f"; then
    hit "hidden zero-width Unicode in agent-instruction file: $f"
  fi
done

# --- 3. exfiltration domains (anywhere in the tree) -----------------------
# Hosts the campaigns POST stolen credentials to:
#   api.masscan.cloud, git-tanstack.com, *.getsession.org (Mini Shai-Hulud);
#   webhook.site (generic dead-drop reused across waves).
EXFIL_RE="api\.masscan\.cloud|git-tanstack\.com|getsession\.org|webhook\.site"
# ChainDrop (2026-08) resolves these four from an ETH contract at runtime, so they
# only BACKSTOP a build that hardcodes one; the contract is in $MARKERS below.
EXFIL_RE="$EXFIL_RE|npm-cache\.com|awqhnjewqjkl\.icu|pypi-get\.com|js-mirror\.com"
# node-ipc (2026-05) DNS-tunnels to this typosquat of Azure Static Web Apps.
EXFIL_RE="$EXFIL_RE|sh\.azurestaticprovider\.net"
# KEY-DECISION 2026-08-22: Shai-Hulud 1.0's webhook.site exfil ID (bb8ca5f6-...)
# adds no coverage. The bare domain above already matches every file carrying it.
# One `git grep` over the whole tree instead of forking a grep per tracked file
# (an O(files) fork storm — ~3s on a 900-file repo). git grep is a single
# multithreaded process; the (usually empty) match list is then filtered through
# the bash allowlist so `is_allowed` semantics stay byte-identical. `|| true`:
# git grep exits 1 when nothing matches, which is the common (clean) case.
while IFS= read -r f; do
  is_allowed "$f" && continue
  hit "known exfiltration domain referenced: $f"
done < <(git grep -EliI "$EXFIL_RE" 2>/dev/null || true)

# --- 4. campaign marker strings -------------------------------------------
# Every literal is split, so this script is not its own match under any filename.
MARKERS=(
  "SHA1""HULUD"                                            # Shai-Hulud 2.0 runner agent name
  "IfYouRevokeThisToken""ItWillWipeTheComputerOfTheOwner"  # ransom token description
  "thebeautiful""marchoftime"                              # Miasma/Hades C2-discovery fallback
  "thebeautiful""snadsoftime"                              # the same, sic
  # ChainDrop (2026-08) resolves its C2 from this ETH contract at runtime, which
  # makes the address the only on-disk constant of the whole campaign.
  "0xE1f2395ee43e45A1""556EC6438a88c31B83493103"
  # "A9-0522" build (2026-08), field-observed, no vendor advisory: a lower provenance
  # tier. splitStrings chunks its hosts, so unsplit literals are the only handles.
  "A9-""0522-4"                                            # build tag, assigned to global.i
  "0xa32""2e5f3"                                           # lead chunk of the C2-resolver wallet
  ":443/0x/(cl|ls)"                                        # C2 endpoint paths
  "Payload-""B6"                                           # chunk of the required X-Payload-B6 header
  # node-ipc 9.1.6/9.2.3/12.0.1 (2026-05): an 80KB IIFE appended to node-ipc.cjs,
  # so it fires on require() with no lifecycle hook. Two payload constants.
  "0123456789""GHJKMP"                                     # custom base-16 alphabet, I/L/N/O skipped
  "qZ8pL3vNxR9""wKmTyHbVcFgDsJaEoUi"                       # hardcoded HMAC key
  # Injection TECHNIQUE, campaign-agnostic: obfuscator.io's string-array accessor
  # alias. A repo committing its own obfuscated bundle needs an allow-glob.
  "const _0x[0-9a-f]{4,6}=_0x[0-9a-f]{4,6};"
)
# Portable join, not `${MARKERS[*]}`: IFS-join semantics differ across shells.
MARKER_RE=""
for m in "${MARKERS[@]}"; do MARKER_RE="${MARKER_RE:+$MARKER_RE|}$m"; done
# Single git grep, same batching as the exfil pass above. Case-INsensitive: an
# ETH address is checksum-cased, so case is not part of any IOC here.
while IFS= read -r f; do
  is_allowed "$f" && continue
  hit "campaign marker string present: $f"
done < <(git grep -EliI "$MARKER_RE" 2>/dev/null || true)

# Known payload SHA-256 hashes (Mini Shai-Hulud), pinned for defense in depth.
KNOWN_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" # router_init.js
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" # tanstack_runner.js
  # node-ipc.cjs is the real package's CJS entry, so this wave is hash-only: the
  # filename is legitimate and cannot go in BAD_BASENAMES above.
  "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144" # node-ipc.cjs (2026-05)
)
if command -v shasum >/dev/null 2>&1; then HASHER=(shasum -a 256); else HASHER=(sha256sum); fi
for f in "${TRACKED[@]}"; do
  case "$f" in *.js|*.mjs|*.cjs) ;; *) continue ;; esac
  sum="$("${HASHER[@]}" "$f" | awk '{print $1}')"
  for h in "${KNOWN_HASHES[@]}"; do
    [[ "$sum" == "$h" ]] && hit "file matches known malicious payload hash: $f"
  done
done

# --- 5. risky package.json lifecycle scripts ------------------------------
# The worm injects preinstall/postinstall/prepare hooks that run its dropper.
# A build-script allowlist blocks DEPENDENCY scripts, but a hook in a
# ROOT/workspace package.json still runs — flag the known dropper invocations
# and the bun-install-pipe pattern.
SCRIPT_RE='(tanstack_runner\.js|setup_bun\.js|bun_environment\.js|set_bun\.js|router_init\.js|bun\.sh/install)'
for f in "${TRACKED[@]}"; do
  [[ "${f##*/}" == "package.json" ]] || continue
  if grep -EqI "\"(pre|post)?(install|prepare)\"[^}]*$SCRIPT_RE" "$f"; then
    hit "package.json lifecycle script invokes known dropper: $f"
  fi
done

# --- verdict --------------------------------------------------------------
if (( ${#HITS[@]} > 0 )); then
  echo "::error::Supply-chain tripwire FAILED — Shai-Hulud IOC(s) detected:"
  for h in "${HITS[@]}"; do
    echo "  - $h"
  done
  echo ""
  echo "This pipeline is BLOCKED to prevent credential exfiltration."
  echo "If this is a false positive, inspect each file above by hand before"
  echo "overriding. Do NOT re-run with secrets until cleared. Rotate any"
  echo "deploy tokens, cloud keys, and npm/GitHub tokens if in doubt."
  exit 1
fi

echo "Supply-chain tripwire passed — no known Shai-Hulud IOCs in tracked files."
