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
# IOC sources (2025-09 -> 2026-06 campaigns):
#   - Microsoft Security: "Shai-Hulud 2.0" (2025-12-09)
#   - StepSecurity / Snyk / Sophos: "Mini Shai-Hulud" (2026-05)
#   - Socket.dev: "Mini Shai-Hulud / Miasma / Hades" PyPI + MCP wave (2026-06)
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

# --- 3. exfiltration domains (anywhere in the tree) -----------------------
# Hosts the campaigns POST stolen credentials to:
#   api.masscan.cloud, git-tanstack.com, *.getsession.org (Mini Shai-Hulud);
#   webhook.site (generic dead-drop reused across waves).
EXFIL_RE="api\.masscan\.cloud|git-tanstack\.com|getsession\.org|webhook\.site"
for f in "${TRACKED[@]}"; do
  is_allowed "$f" && continue
  if grep -EqiI "$EXFIL_RE" "$f"; then
    hit "known exfiltration domain referenced: $f"
  fi
done

# --- 4. campaign marker strings -------------------------------------------
# Runner-agent name, ransom token description, and worm self-identifiers.
# Assembled from fragments so this script is not its own match.
SHA1HULUD="SHA1""HULUD"                       # Shai-Hulud 2.0 runner agent name
RANSOM="IfYouRevokeThisToken""ItWillWipeTheComputerOfTheOwner"
BEAUTIFUL1="thebeautiful""marchoftime"        # Miasma/Hades — C2-discovery fallback string
BEAUTIFUL2="thebeautiful""snadsoftime"        # Miasma/Hades — C2-discovery fallback string (sic)
MARKER_RE="${SHA1HULUD}|${RANSOM}|${BEAUTIFUL1}|${BEAUTIFUL2}"
for f in "${TRACKED[@]}"; do
  is_allowed "$f" && continue
  if grep -EqI "$MARKER_RE" "$f"; then
    hit "campaign marker string present: $f"
  fi
done

# Known payload SHA-256 hashes (Mini Shai-Hulud), pinned for defense in depth.
KNOWN_HASHES=(
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" # router_init.js
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" # tanstack_runner.js
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
