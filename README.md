# shai-hulud-tripwire

A fail-fast CI guard against the **Shai-Hulud / Mini Shai-Hulud** self-spreading
npm worm (2025-09 to 2026-08 waves). It runs as the **first** job in your
pipeline, holds **no secrets**, and does a pure git-tree scan — no
`npm/pnpm install`, no network. Gate every secret-holding job (`build`,
`deploy`, `publish`) behind it with `needs:`, and a force-pushed or
dependency-injected payload is blocked **before** any runner that holds deploy
tokens, cloud keys, or npm/GitHub tokens ever executes.

> **Why this exists:** Socket/threat-DB scanners catch malicious *packages*.
> They don't catch the worm's **persistence layer** — a planted GitHub Actions
> workflow that dumps `toJSON(secrets)`, a `prepare` lifecycle hook, or a
> dead-drop payload file committed to your repo. This catches that layer.

## Use it (pick one)

### 1. Reusable workflow — recommended

Gives you the complete isolated, zero-secret gating job. Add to your `ci.yml`:

```yaml
jobs:
  tripwire:
    uses: notambourine/shai-hulud-tripwire/.github/workflows/tripwire.yml@v1

  build:
    needs: tripwire          # build/deploy can't start until the scan is green
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... your build/deploy steps (where secrets first appear) ...
```

### 2. Composite action — one step inside a job you already have

```yaml
jobs:
  guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4          # required — composite actions don't auto-checkout
      - uses: notambourine/shai-hulud-tripwire@v1
```

### 3. Org-wide, zero opt-in (org admins)

Configure a **required workflow** / org ruleset so the check is injected into
every repo in the org automatically, with no per-repo edit. Settings →
(org) → Actions → *Required workflows*, pointing at
`notambourine/shai-hulud-tripwire/.github/workflows/tripwire.yml`.

### 🔒 Pin by SHA

A referenced action is itself a supply-chain dependency — don't let your worm
guard become the injection point. For production, pin to a commit SHA instead
of the moving `v1` tag:

```yaml
uses: notambourine/shai-hulud-tripwire@<full-40-char-sha>   # v1.x.y
```

## What it catches

| Class | Examples |
|---|---|
| Dead-drop payload files | `router_init.js`, `tanstack_runner.js`, `setup_bun.js`, `bun_environment.js`, `set_bun.js`, `gh-token-monitor.sh`, `router_runtime.js`, `langchain_core-setup.pth`, `ensmallen_haswell.abi3.so`, `ensmallen_core2.abi3.so` |
| Agent/editor persistence hooks | `.claude/setup.mjs`, `.vscode/setup.mjs`, `.claude/router_runtime.js` |
| Python `.pth` startup hooks | any tracked `*.pth` running an `import …; exec/os/subprocess` one-liner (Miasma/Hades PyPI wave) |
| Secret-exfil workflows | any `.github/workflows/*` using `toJSON(secrets)` |
| Campaign dropper workflow | `shai-hulud-workflow.yml` by name (Checkmarx published the name only, so the body is not greppable) |
| Hidden Unicode in agent configs | zero-width codepoints in a tracked `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `copilot-instructions.md`, or anything under `.claude/` or `.cursor/` (TrapDoor). Emoji ZWJ, a leading BOM, and Persian/Urdu/Hindi ZWNJ orthography are exempt |
| Exfiltration domains | `api.masscan[.]cloud`, `git-tanstack[.]com`, `*.getsession[.]org`, `webhook[.]site`, ChainDrop's `npm-cache[.]com` / `awqhnjewqjkl[.]icu` / `pypi-get[.]com` / `js-mirror[.]com`, node-ipc's `sh.azurestaticprovider[.]net` |
| Campaign markers | the `SHA1[-]HULUD` runner name, the ransom token description, the `thebeautiful[march]oftime` / `thebeautiful[snads]oftime` C2-discovery strings, ChainDrop's `0xE1f2…3103` C2 contract, the `A9[-]0522` build tag with its resolver wallet and `:443/0x/…` endpoints, node-ipc's HMAC key and custom base-16 alphabet, and obfuscator.io's `const _0x…=_0x…;` accessor alias |
| Known payload hashes | published SHA-256 of `router_init.js`, `tanstack_runner.js`, and the trojaned `node-ipc.cjs` |
| Malicious lifecycle hooks | `package.json` `preinstall`/`postinstall`/`prepare` invoking a known dropper or `bun.sh/install` |

Domains and markers above are defanged (`[.]`, `[-]`) so this README never
trips the scanner it documents.

The obfuscator.io accessor alias is the one marker here that names a *technique*
rather than a campaign, so it is also the only one with a plausible false
positive: a repo that commits its own obfuscated bundle should exempt that path
with `allow-globs` below.

Filename, hash, and lifecycle-script checks are never exempted. Content scans
(workflows/domains/markers) skip the scanner itself; if your repo *documents*
these IOCs (e.g. a security README), exempt it:

```yaml
- uses: notambourine/shai-hulud-tripwire@v1
  with:
    allow-globs: "*SECURITY.md"        # newline- or space-separated globs
```

## Defense in depth

This is the **persistence-artifact** layer. Pair it with package-level defenses:

- **Socket Firewall** (`socketdev/action@v1`) — vets each package against a threat DB at install time.
- **Build-script allowlist** — pnpm `onlyBuiltDependencies`, or `npm ci --ignore-scripts`.
- **Lockfile strictness** — `npm ci` / `pnpm install --frozen-lockfile`.

## ⚠️ The force-push gap — requires a branch ruleset

This CI job **cannot** defend against a force-push that also rewrites or
deletes the gating job itself: whoever can rewrite the branch can rewrite the
workflow. Close it with a GitHub **ruleset** on your protected branches:

```bash
gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
{
  "name": "protect-default-branches",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "non_fast_forward" },
    { "type": "deletion" },
    { "type": "pull_request",
      "parameters": { "required_approving_review_count": 1, "dismiss_stale_reviews_on_push": true } },
    { "type": "required_status_checks",
      "parameters": { "strict_required_status_checks_policy": true,
        "required_status_checks": [ { "context": "Supply-chain tripwire (Shai-Hulud IOCs)" } ] } }
  ]
}
JSON
```

## Run locally

```bash
bash scripts/supply-chain-tripwire.sh
```

## Updating the IOC list

New campaign waves publish new filenames/domains. Add them to the relevant
array/regex in `scripts/supply-chain-tripwire.sh`, run the self-test
(`.github/workflows/self-test.yml`), and cut a new tag. Keep marker literals
fragmented (e.g. `"SHA1""HULUD"`) so the scanner never matches its own source.

## Sources

- Checkmarx: *Shai-Hulud 1.0* (2025-09), the `shai-hulud-workflow.yml` dropper
- Microsoft Security — *Shai-Hulud 2.0* (2025-12-09)
- StepSecurity: trojaned `node-ipc` 9.1.6 / 9.2.3 / 12.0.1 (2026-05)
- Phoenix Security: *TrapDoor* hidden-Unicode agent-config poisoning (2026-05)
- StepSecurity / Snyk / Sophos — *Mini Shai-Hulud* (2026-05)
- Socket.dev — *Mini Shai-Hulud / Miasma / Hades worms target bioinformatics and MCP developers* (2026-06)
- Elastic / Microsoft / JFrog: *ChainDrop* keyv wave, on-chain C2 (2026-08)
- Unit 42 — npm supply-chain attack tracking
- CISA — widespread npm ecosystem compromise alert

The `A9[-]0522` markers are field-observed with no vendor advisory behind them,
a lower provenance tier than everything above.

## License

MIT — see [LICENSE](LICENSE).
