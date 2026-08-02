# tomofound

> *tomo* (友) — friend, ally · *found* — to discover, to establish

We are entering an era where AI assistants do not work alone. They call tools, run plugins, load skills, and extend their reach through connectors built by developers around the world. This power is extraordinary — and so is the trust we place in it every time we install an extension.

**tomofound** was born from a simple belief: no one should have to navigate that trust alone.

The name carries two meanings at once. *Tomo* (友) is the Japanese word for friend — an ally who walks beside you, watches your back, and tells you the truth. *Found* speaks to discovery and to building something that lasts. Together they describe what this tool aspires to be: not a gatekeeper, but a companion that surveys the landscape with you, flags what it finds, and helps you decide with confidence.

Security has always been a collective endeavor. The threat intelligence here — ATR catalog rules, CVE databases, OSV advisories — exists because countless researchers shared what they discovered. This project exists because contributors gave their time and judgment. Every new threat pattern added, every edge case reported, every idea offered makes the next user a little safer.

If you work with AI tools and care about the people who use them, **you are already part of this**. Open an issue. Propose a rule. Share a finding. The more voices that join, the stronger the signal becomes — and the safer AI becomes for everyone.

---

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini CLI, and Codex CLI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, prompt injection, MCP tool poisoning, and memory poisoning — before or after installation. Combines Trivy CVE/secret scanning, Python AST + taint-tracking static analysis, and optional LLM semantic review, then emits a 0–100 risk score with an install recommendation.

## How it works

tomofound is **install once, then use it from Claude, Codex, or Gemini CLI**:

1. Run `setup.sh` one time to install the MCP server and scan-rule prompt.
2. Add the scan-rule prompt as a **Skill** in Claude Desktop App (one-time drag-and-drop).
3. From then on, type `/security-scan` in any Claude **chat** to scan — no further setup, no per-scan installation. The installer has already fetched the rule catalog and Trivy, so the first scan is a scan, not a download.

## Requirements

- macOS
- [Claude desktop app](https://claude.ai/download) (for Claude usage)
- Codex (for Codex usage)
- [Gemini CLI](https://github.com/google-gemini/gemini-cli) (for Gemini CLI usage)
- Python 3 (preinstalled on macOS)
- `git` on PATH (only needed when you pass a `https://github.com/...` URL)

## Installation (one-time)

### Step 1 — Run the installer

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

By default this configures Claude, Codex, and Gemini CLI.

The one-liner fetches `setup.sh` from `main`, but **the installer itself pulls the server and skill from a pinned release tag**, not from the branch. tomofound pins Trivy, the ATR catalog and the mcp SDK for exactly this reason; serving its own source off a moving branch while making that argument about everyone else's would not hold up. A commit merged to `main` does not reach new installs until a release bumps the pin. The installer prints which tag it is using.

To install unreleased code deliberately:

```bash
TOMOFOUND_REF=main bash -c "$(curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh)"
```

It says so on the way past. Note this narrows the trusted window rather than closing it — `setup.sh` is still read from `main`, since a `curl | bash` URL has to point somewhere. That file is ~250 lines and is the one piece a wary user can realistically read before piping it to a shell; the ~2,500 lines of server code it installs are now pinned.

```bash
# Claude only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --claude

# Codex only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --codex

# Gemini CLI only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --gemini
```

### Step 2 — Register the skill in Claude Desktop App

1. Open Claude Desktop App.
2. Open **Settings → Customize → Skills**.
3. Drag `~/.tomofound/skills/security-scan/security-scan.md` into the Skills list.
4. Quit Claude fully (**Cmd-Q**) and reopen it.
5. Verify: type `/` in any **chat** — `/security-scan` should appear in the slash menu.

> Claude Desktop copies the file when you add it, so this registration is a **snapshot**. Upgrading tomofound later refreshes the file on disk but not Claude's copy — you'll need to re-add it. See [Updating](#2-updating-the-skill-inside-claude-desktop-manual).

### Step 2 (Codex) — Restart Codex

Restart Codex or open a new thread. The `security-scan` skill should be available and the `tomofound` MCP tools should load.

### Step 2 (Gemini CLI) — Restart Gemini CLI

Restart Gemini CLI or open a new session. The `security-scan` skill is installed to `~/.gemini/skills/security-scan/SKILL.md` and should be available for invocation.

### What the installer does

1. Copies the MCP server (`trivy_server.py`) and the scan-rule prompt (`security-scan.md`) into `~/.tomofound/`
2. Builds the Python virtualenv at `~/.tomofound/venv/` and installs the pinned dependencies
3. Downloads the pinned ATR rule catalog (~28 MB) into `~/.tomofound/catalogs/atr/`
4. Downloads and SHA-256-verifies the pinned Trivy binary (~48 MB archive) into `~/.tomofound/tools/`
5. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json`
6. Installs the Codex skill wrapper into `~/.codex/skills/security-scan/SKILL.md`
7. Registers the `tomofound` MCP server in `~/.codex/config.toml`
8. Installs the Gemini CLI skill wrapper into `~/.gemini/skills/security-scan/SKILL.md`

Steps 2–4 print progress as they go and are **not fatal**: if a download fails the installer says so and finishes, and the scanner runs with reduced coverage until you fetch them later. Skip them entirely with `--no-downloads` on a metered or air-gapped machine.

Doing this work in the installer is deliberate. The alternative — building the venv on Claude Desktop's first server start and fetching Trivy inside a scan — puts long operations behind deadlines nobody controls, which is how a scan ends up quietly matching an eleven-release-old catalog, or a Trivy install times out and caches nothing.

After this, you can forget about installation — just use `/security-scan` in Claude chat, the `security-scan` skill in Codex, or the `security-scan` skill in Gemini CLI.

### Updating

Three things update on **different schedules**, and the installer only handles the first. Skipping the other two is the most common reason a scan silently runs old code or old rules.

| What | How it updates | Automatic? |
|---|---|---|
| tomofound itself (server, prompt source, MCP registration) | re-run the installer | yes, on re-run |
| The skill **registered inside Claude Desktop** | re-add it by hand — see below | **no** |
| The ATR rule catalog | `atr_update` from your assistant | **no, never** |

#### 1. tomofound itself

Re-run the same `curl | bash` command. Installation is **idempotent** — re-running is always safe. At the start the installer prints a summary of what it found at `~/.tomofound/` and what it will touch:

- **Refreshed:** server Python modules, the security-scan prompt **at `~/.tomofound/skills/`**, the MCP-server registration in Claude / Codex configs.
- **Preserved:** the venv (its `_DEPS_VERSION` marker auto-refreshes deps on the next server start if anything changed), cached ATR catalogs, the Trivy binary, and your historical scan reports under `~/.tomofound/reports/`.
- **Reported as orphans:** any `*.py` in `~/.tomofound/server/` that this version no longer ships. The installer doesn't delete them — you decide.

#### 2. Updating the skill inside Claude Desktop (manual)

When you drag `security-scan.md` into **Settings → Customize → Skills**, Claude Desktop takes **its own copy**. The installer cannot reach that copy, so refreshing `~/.tomofound/skills/` changes nothing about what Claude actually runs. Your registered skill keeps working — at whatever version you first added.

To pick up a new version:

1. Re-run the installer (step 1) so `~/.tomofound/skills/security-scan/security-scan.md` is current.
2. Open **Settings → Customize → Skills**, remove the existing `security-scan` entry, and drag the refreshed file back in.
3. Quit Claude fully (**Cmd-Q**) and reopen it.

Codex and Gemini CLI read their skill files from disk each session, so for those the installer alone is enough — restart the client and you're current.

If you only need the checklist and not the slash command, `/tomofound__security_scan` comes from the MCP server directly and is always at the installed version, no re-registration involved.

#### 3. Updating the ATR rule catalog (manual, on purpose)

The catalog is **never** fetched automatically. It is the one part of tomofound that reaches the network on your behalf during normal use, so it only moves when you ask:

```
Call the atr_update MCP tool          (or just ask: "run atr_update")
```

Ask your assistant to run it, or invoke the tool directly. It downloads the pinned ATR release, re-verifies the upstream LICENSE is still MIT before trusting the tarball, and re-parses every rule into `~/.tomofound/catalogs/atr/`.

**Re-running the installer does not do this.** Upgrading tomofound changes which ATR version is *pinned*; it does not touch the catalog already on disk. Until you run `atr_update`, scans keep matching the rules you downloaded last time — potentially many releases and hundreds of rules behind.

The report header calls this out rather than showing a green tick for a stale catalog:

```
⚠️ Agent Threat Rules (ATR) v3.5.0 (244 rules) — STALE: this build pins
   v3.5.11; run atr_update before trusting these results
```

Check the current state any time with the `atr_status` tool, or `catalogs_status` for ATR, OSV and Trivy together. Trivy is flagged the same way if the binary on your machine is off the pinned version — it is reused as-is once installed, including a `brew install trivy` of your own.

If you want a genuinely fresh install (e.g. clearing reports), use `--clean`:

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --clean
```

`--clean` wipes the entire `~/.tomofound/` directory after a 5-second confirm window. The MCP server registration in `claude_desktop_config.json` / `~/.codex/config.toml` is re-written either way.

## Troubleshooting

### MCP server won't start / dies immediately

- Verify Python 3.10+: `~/.tomofound/venv/bin/python --version`
- Check the MCP SDK is installed: `~/.tomofound/venv/bin/pip list | grep -i mcp`
- Re-run `setup.sh` to refresh server files and let the bootstrap reinstall dependencies on next start.

### Trivy download fails / times out

The Trivy archive is **~48 MB** (it expands to a ~165 MB binary). A scan will fetch it automatically, but only within a short budget — long enough on a fast link, and deliberately not long enough to hold the request open past your client's timeout. If it doesn't finish, the scan reports `trivy_unavailable` and continues without CVE/secret coverage rather than hanging.

- **Install it once, on purpose:** ask your assistant to run the `install_trivy` tool. Same download, same SHA-256 verification, but as its own call with the full budget instead of a scan waiting on it. Then rescan.
- Check network connectivity and proxy settings — the fetch goes to `github.com`.
- Or install Trivy yourself (`brew install trivy`, or download from [GitHub releases](https://github.com/aquasecurity/trivy/releases)) and put it on `PATH`. tomofound uses an install you manage as-is; see the off-pin note under [Updating](#updating).
- If the SHA-256 verification fails, retry; persistent failures suggest a network integrity issue (transparent proxy, captive portal). tomofound refuses to install an unverified binary and falls back to LLM-only rather than run it.

Trivy is optional throughout. Without it you lose the CVE and secret passes; ATR, the Python AST/taint analysis, and LLM review all still run.

### ATR catalog not downloading

- Confirm you can reach `github.com` (the catalog is fetched from the Agent-Threat-Rule repo).
- Manually trigger a refresh by invoking the `atr_update` MCP tool.
- Check available disk space in `~/.tomofound/` — the catalog needs a few MB.

### Scan hangs or takes too long

- Pass `time_budget_seconds` to `atr_scan_path` to cap scan time (e.g. 60 seconds).
- Scan individual plugin directories rather than an entire `~/.claude/` tree at once.
- If a scan returns `budget_exceeded`, re-invoke on a narrower path.

### "No findings" but expected results

- Check the ATR catalog is installed by invoking the `atr_status` tool — if the catalog is missing, run `atr_update` first.
- **Check it isn't stale.** `atr_status` reports the cached version; if it differs from the pinned one the header shows `STALE` and the scan is matching whatever you downloaded last time. Run `atr_update`. See [Updating](#3-updating-the-atr-rule-catalog-manual-on-purpose).
- Verify the target path exists and contains scannable files by running the `discover_targets` tool.
- Ensure extensions are installed in their standard locations (`~/.claude/`, `~/.codex/`, `~/.gemini/`).

### I upgraded tomofound but nothing changed

Three things update separately — see [Updating](#updating). In order of how often it catches people:

- **The skill in Claude Desktop keeps its own copy.** Re-running the installer refreshes `~/.tomofound/skills/` but not what Claude runs. Remove and re-add the skill under **Settings → Customize → Skills**, then Cmd-Q and reopen. Codex and Gemini CLI don't have this problem — they read from disk each session.
- **The ATR catalog never auto-updates.** A new tomofound version changes which ATR release is *pinned*; the rules on disk stay put until you run `atr_update`.
- **Trivy is reused once installed.** A binary already on `PATH` or in `~/.tomofound/tools/` is used as-is even if this build pins a newer one. The report flags it; delete the binary to let tomofound install the pinned build.

### `/security-scan` says "unknown skill"

The registered skill predates the fix that aligned its declared name with its directory. Re-add it (see above). `/tomofound__security_scan` works meanwhile — that name comes from the MCP server and never changed.

### setup.sh errors

- **"Not macOS"**: tomofound currently supports macOS only; Linux support is planned.
- **Permission denied**: check ownership of `~/.tomofound/` (`ls -la ~/.tomofound`).
- For a clean slate, re-run setup.sh with `--clean` to wipe and recreate the installation directory.

### Uninstall

```bash
# Remove server, reports, and auto-installed Trivy binary
rm -rf ~/.tomofound
```

Then:

1. In Claude Desktop App, open **Settings → Customize → Skills** and remove `security-scan`.
2. Remove the `"tomofound"` key under `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json` (edit by hand — the file holds other Claude preferences too).

## Usage

Once installed, the scan entry point is always available. No need to re-run `setup.sh` between scans. Use Claude Desktop App **chat** (not Cowork) for the most reliable experience.

### Claude (chat)

Type `/security-scan` in any Claude chat window, then follow it with a target:

```
# Scan everything installed on this Mac
/security-scan

# Scan only Claude Code plugins / skills / agents / commands
/security-scan --target claude

# Scan only Gemini CLI config + extensions
/security-scan --target gemini

# Scan only Codex CLI config + prompts
/security-scan --target openai

# Pre-install — scan a local directory
/security-scan ~/Downloads/plugin-dir/

# Pre-install — scan a public GitHub repo
/security-scan https://github.com/user/plugin

# Pre-install — scan a .zip archive (local path or https URL)
/security-scan ~/Downloads/plugin.zip
/security-scan https://example.com/plugin.zip
```

### Codex

Invoke the `security-scan` skill when asking Codex to audit installed extensions, a local path, a `.zip` archive, or a public GitHub repository. Codex uses the same Tomofound MCP server and writes reports to the same `~/.tomofound/reports/` directory.

### Gemini CLI

Invoke the `security-scan` skill when asking Gemini CLI to audit installed extensions, a local path, a `.zip` archive, or a public GitHub repository. Gemini CLI uses the same Tomofound MCP server and writes reports to the same `~/.tomofound/reports/` directory.

## What it scans

| Item | Method | Detects |
|------|--------|---------|
| Plugins & connectors (`.ts` `.js` `.py` `.go` `.rs` `.sh`) | Trivy + AST/taint + LLM | Secrets, backdoors, data exfiltration, CVEs, supply-chain issues, MCP tool poisoning |
| Skills, agents, prompts (`.md`, `AGENTS.md`) | LLM | Prompt injection, behaviour override, memory poisoning, system prompt leakage, social engineering |
| MCP configs (`.mcp.json`, inline `mcpServers`) | LLM | Malicious launch commands, suspicious URLs, hardcoded credentials |
| Config files (`settings.json`, `oauth_creds.json`, `auth.json`, `config.toml`) | LLM | Plaintext credentials, overly permissive settings |

Python sources additionally get **AST analysis** (catches `eval` / `exec` / `pickle.loads` / `subprocess(shell=True)` / obfuscated dynamic dispatch) and **taint tracking** (flags untrusted input — env vars, `sys.argv`, `input()`, network responses, MCP handler arguments — flowing into a code-execution or shell sink).

Trivy is auto-installed to `~/.tomofound/tools/trivy` on first scan if it isn't already on `PATH`.

## Risk score

Each scan produces a 0–100 risk score (severity-weighted across all findings) and an install recommendation:

| Score | Recommendation |
|-------|----------------|
| 0 | ✅ Safe |
| 1–15 | 🔵 Caution |
| 16–50 | ⚠️ High Risk |
| 51–100 | 🚫 Avoid |

## How rules work

Detection rules live in `skills/security-scan/security-scan.md` (installed locally to `~/.tomofound/skills/security-scan/security-scan.md`). The MCP server loads this file at startup and serves it as the Claude `/security-scan` prompt. Codex uses `integrations/codex/skills/security-scan/SKILL.md` and Gemini CLI uses `integrations/gemini/skills/security-scan/SKILL.md` as lightweight skill wrappers around the same MCP tools. To add a shared scan rule, edit the Claude prompt and the Codex/Gemini wrappers as needed, then re-run the installer.

## Reports

Each scan writes three files under `~/.tomofound/reports/`, sharing a `YYYY-MM-DD-HH-MM` timestamp:

| File | Format | Use |
|------|--------|-----|
| `*.md` | Markdown | Human-readable report (primary) |
| `*.json` | JSON | Structured raw findings, score, and counts |
| `*.sarif` | SARIF 2.1.0 | CI/CD upload (GitHub code scanning, Azure DevOps, GitLab) — Trivy CVEs, secrets, and misconfigurations are normalised into the same finding shape as AST / taint / LLM findings, so every result has a rule ID and file location |

## Supply chain

tomofound is itself a piece of software you run with elevated trust, so we list every external dependency and outbound network call it makes. **Source changes that touch this list MUST update the tables below in the same PR** (the repo-root `CLAUDE.md` enforces this for AI-assisted contributions).

### Runtime dependencies

| Component | Version | License | Source | Notes |
|-----------|---------|---------|--------|-------|
| Python `mcp` SDK | `1.28.1` (exact pin) | [MIT](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE) | https://pypi.org/project/mcp/ | Installed into `~/.tomofound/venv` on first server start by `_bootstrap()` (see `server/trivy_server.py`). Bump the `_PIP_DEPS` list + this table together. |
| Python `PyYAML` | `>=6.0,<7` | [MIT](https://github.com/yaml/pyyaml/blob/main/LICENSE) | https://pypi.org/project/PyYAML/ | Installed alongside `mcp` by `_bootstrap()`. Parses the Agent Threat Rules YAML catalog. |
| Trivy CLI | `0.72.0` (pinned in `server/trivy_server.py:_TRIVY_PIN`) | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | https://github.com/aquasecurity/trivy | Downloaded on first scan from the pinned release tag, verified against Trivy's published sha256 checksums, then cached at `~/.tomofound/tools/trivy`. **Deliberately pinned, not floating-latest**: Trivy's March 2026 supply-chain incident shipped a malicious release with matching checksums — a floating `releases/latest` install cannot survive that attack. Bumping the pin is an explicit, reviewed change. Trivy's CVE *database* still auto-updates independently of the binary version. |
| OSV vulnerability API | API v1 (live) | [Apache-2.0](https://github.com/google/osv.dev/blob/master/LICENSE) (engine); upstream advisory licenses for individual entries | https://osv.dev | Queried by the `check_osv` MCP tool as a fallback when Trivy has no dependency manifest. Findings cite the OSV advisory ID. |
| Agent Threat Rules (ATR) catalog | `v3.5.11` (pinned in `server/atr_catalog.py:ATR_PIN`) | [MIT](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v3.5.11/LICENSE) | https://github.com/Agent-Threat-Rule/agent-threat-rules | Source tarball downloaded by the user-initiated `atr_update` MCP tool, then cached at `~/.tomofound/catalogs/atr/` (rules + LICENSE retained per MIT). Never auto-updated; `atr_update` re-verifies the upstream LICENSE is still MIT before trusting a new tarball. We use ATR as a regex pre-filter — findings cite rule IDs (`ATR-YYYY-NNNNN`) and upstream references (OWASP Agentic / MITRE ATLAS / CVE). |
| host Python 3 | `≥3.9` | [PSF License](https://docs.python.org/3/license.html) | macOS system | Required for the bootstrap venv. Preinstalled on macOS. |
| host `git` | any recent | [GPL-2.0](https://git-scm.com/about/free-and-open-source) | macOS system | Required only when scanning a `https://github.com/...` URL via `clone_repo`. Used as a CLI subprocess; we do not link git as a library. |
| Python stdlib | ships with host Python | [PSF License](https://docs.python.org/3/license.html) | https://docs.python.org/3/library/ | `ast`, `ipaddress`, `socket`, `subprocess`, `tarfile`, `tempfile`, `urllib`, `zipfile`, etc. |

### Outbound network calls

| URL pattern | Purpose | Who triggers it |
|-------------|---------|-----------------|
| `https://github.com/aquasecurity/trivy/releases/download/v0.72.0/...` | Download the pinned Trivy binary + its published checksums | First scan, when Trivy isn't on `PATH` |
| `https://api.osv.dev/v1/query` | OSV vulnerability lookup (Level-4 fallback when Trivy has no dependency manifest) | The `check_osv` MCP tool |
| `https://github.com/<owner>/<repo>(.git)` | `git clone --depth 1` for pre-install scan of a GitHub URL | The `clone_repo` MCP tool |
| `https://<host>/<path>.zip` | Download a `.zip` for pre-install scan | The `extract_zip` MCP tool — **https only**, refuses private / loopback / link-local / cloud-metadata hosts, re-validates every redirect target |
| `https://raw.githubusercontent.com/rotoyang/tomofound/<release tag>/...` | Installer fetches the server + skill at the pinned tag (`TOMOFOUND_REF`, default the current release; a missing tag fails loudly rather than falling back to `main`) | `setup.sh` only |
| `https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/v3.5.11/LICENSE` | Re-verify ATR upstream license before trusting a catalog refresh | The `atr_update` MCP tool |
| `https://github.com/Agent-Threat-Rule/agent-threat-rules/archive/refs/tags/v3.5.11.tar.gz` | Download the pinned ATR source tarball | The `atr_update` MCP tool — user-initiated only, never auto-run |
| `https://api.github.com/repos/Agent-Threat-Rule/agent-threat-rules/releases/latest` | Report whether a newer ATR release exists than our pin (never downloads) | The `catalogs_status` MCP tool — only when called with `check_upstream: true`; local-only by default |

### Repository assets

| Asset | Source | Notes |
|-------|--------|-------|
| `server/trivy_server.py` | This repo | The MCP server itself |
| `server/python_analyzer.py` | This repo | AST + taint static analysis |
| `skills/security-scan/security-scan.md` | This repo | Detection rules loaded as an MCP prompt |
| `integrations/codex/skills/security-scan/SKILL.md` | This repo | Codex-side wrapper around the same MCP tools |
| `integrations/gemini/skills/security-scan/SKILL.md` | This repo | Gemini CLI-side wrapper around the same MCP tools |
| `setup.sh` | This repo | One-shot installer |

No third-party Python wheels are vendored, no binary blobs ship in the repo, and the installer touches only `~/.tomofound/`, `~/Library/Application Support/Claude/claude_desktop_config.json`, (if Codex is selected) `~/.codex/config.toml` + `~/.codex/skills/security-scan/`, and (if Gemini is selected) `~/.gemini/skills/security-scan/`.

### Attribution

tomofound's scanning pipeline integrates the following independent projects. Each runs under its own license listed above — we use them as documented, attribute them in scan reports, and do not redistribute their data.

- **Trivy** — vulnerability and secret scanning, © [Aqua Security](https://github.com/aquasecurity/trivy), Apache-2.0. Pinned release installed at first scan (checksum-verified); binary lives at `~/.tomofound/tools/trivy`.
- **OSV.dev** — open-source vulnerability database, © [Google](https://github.com/google/osv.dev), Apache-2.0. Queried live as a CVE-fallback source.
- **Model Context Protocol Python SDK** — © [Anthropic, PBC](https://github.com/modelcontextprotocol/python-sdk), MIT. Provides the stdio MCP server runtime our `trivy_server.py` is built on.
- **PyYAML** — © Kirill Simonov and contributors, MIT. Parses the Agent Threat Rules YAML catalog into our internal regex pre-filter.
- **Agent Threat Rules (ATR)** — open detection rule format for AI-agent security threats, © [ATR Contributors](https://github.com/Agent-Threat-Rule/agent-threat-rules), MIT. Pinned to `v3.5.11`; consumed as a regex pre-filter by the `atr_match` MCP tool. Each ATR-sourced finding cites the upstream rule ID (`ATR-YYYY-NNNNN`) and the references the rule defines (OWASP Agentic Top 10, MITRE ATLAS, CVE) — see the rule index at https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/v3.5.11/rules.

When tomofound integrates additional rule or threat-intel catalogs (e.g. Bumblebee), each will be added to this list with its license, upstream URL, and the version we pin. See `docs/catalog-architecture.md` (local design notes) for the license-compliance protocol we follow before integrating any new source.
