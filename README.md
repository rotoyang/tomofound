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

tomofound is **install once, then use it from Claude, Codex, or Gemini CLI**. In Claude Code, installing the plugin ([see below](#claude-code--install-as-a-plugin), from the next release) is the whole setup; for everything else:

1. Run `setup.sh` one time to install the MCP server and scan-rule prompt.
2. Add the scan-rule prompt as a **Skill** in Claude Desktop App (one-time drag-and-drop).
3. From then on, type `/security-scan` in any Claude **chat** to scan — no further setup, no per-scan installation. The installer has already fetched the rule catalog and Trivy, so the first scan is a scan, not a download.

## Requirements

- macOS. **Windows is not supported yet** (the repo has no `setup.ps1`, and `setup.sh` only runs on macOS).
- [Claude desktop app](https://claude.ai/download) (for Claude usage)
- Codex (for Codex usage)
- [Gemini CLI](https://github.com/google-gemini/gemini-cli) (for Gemini CLI usage)
- **Python 3.10 or newer** as `python3` on `PATH` (the `mcp` 1.30.0 SDK requires 3.10+). Both `setup.sh` and the Claude Code plugin need it; the plugin runs `python3` directly. On macOS, `python3` may be Apple's Command Line Tools stub: without Command Line Tools it opens an install prompt, and Apple's bundled Python is older than 3.10. Install Python 3.10+ (from [python.org](https://www.python.org/downloads/) or Homebrew) and check with `python3 --version`.
- `git` on PATH (only needed when you pass a `https://github.com/...` URL)

## Installation (one-time)

Pick the path that matches where you use tomofound:

| You use… | Install with |
|---|---|
| **Claude Code** | the plugin — [below](#claude-code--install-as-a-plugin) |
| **Claude Desktop chat**, **Codex**, **Gemini CLI** | `setup.sh` — [Step 1](#step-1--run-the-installer) onward |

Both paths use the same MCP server and the same `~/.tomofound/` data directory, so reports, the ATR catalog and Trivy are shared if you install both.

### Claude Code — install as a plugin

> **Available from the next release.** The plugin is served from a release tag, and the current tag (`v0.5.0`) does not contain the plugin files yet. Until a release ships them, use `setup.sh` below.

Inside Claude Code:

```
/plugin marketplace add rotoyang/tomofound
/plugin install tomofound@tomofound
```

Then run the skill as **`/tomofound:security-scan`** (plugin skills are namespaced by plugin name). The plugin registers the `tomofound` MCP server itself — there is no `claude_desktop_config.json` edit and no drag-and-drop skill step.

A `SessionStart` hook runs `trivy_server.py --ensure-tools` in the background (async, 600-second limit). It is a no-op once the venv dependencies, the pinned ATR catalog and Trivy are all in place. Otherwise it fills in what is missing, so your first scan is a scan, not a download:

- **Trivy** is downloaded only if it is neither on `PATH` nor already in `~/.tomofound/tools/`.
- **The ATR catalog** is downloaded only when the cached catalog is not the pinned version: it is missing, or it was left over from before a tomofound upgrade changed the pin. The hook never fetches `latest`, and a catalog already at the pin is left alone.

Each ATR download first re-verifies that the upstream LICENSE is still MIT, the same check `atr_update` makes. The hook never blocks Claude Code from starting, and it writes to `~/.tomofound/` exactly as the installer does — the plugin does **not** move data into Claude Code's plugin data directory.

The plugin is pinned the same way as the installer: the marketplace points at a release tag, never at `main`, so nothing merged to `main` reaches `/plugin install` until a release says so.

**Prerequisites:** the plugin starts its MCP server and the `SessionStart` hook with `python3` from `PATH`, so the `python3` that a new shell finds must be Python 3.10+ (see [Requirements](#requirements)). If it is missing or too old, the server will not start. Windows is **not supported yet**.

#### Moving from `setup.sh` to the plugin (Claude Code)

If you ran `setup.sh` earlier and had also registered `tomofound` as a Claude Code MCP server (for example with `claude mcp add` or `claude mcp add-from-claude-desktop`), that registration and the plugin's would both start a `tomofound` server. Remove the old one first:

```bash
claude mcp list                              # look for a standalone "tomofound"
claude mcp remove tomofound --scope user     # or --scope local / --scope project, whichever list shows
```

`claude mcp remove` only looks in the local scope unless you pass `--scope`, so a user-scope entry reports "No local MCP server found" without it.

- `setup.sh` itself only writes `~/Library/Application Support/Claude/claude_desktop_config.json` (and the Codex/Gemini files), never Claude Code's own config, so for many users there is nothing to remove.
- **Do not** delete the `tomofound` entry from `claude_desktop_config.json` if you still use Claude Desktop chat, Codex or Gemini CLI — those keep using `setup.sh`.
- Keep `~/.tomofound/`. The plugin reuses it; deleting it only forces a re-download.

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
3. Drag `~/.tomofound/skills/security-scan/SKILL.md` into the Skills list.
4. Quit Claude fully (**Cmd-Q**) and reopen it.
5. Verify: type `/` in any **chat** — `/security-scan` should appear in the slash menu.

> Claude Desktop copies the file when you add it, so this registration is a **snapshot**. Upgrading tomofound later refreshes the file on disk but not Claude's copy — you'll need to re-add it. See [Updating](#2-updating-the-skill-inside-claude-desktop-manual).

### Step 2 (Codex) — Restart Codex

Restart Codex or open a new thread. The `security-scan` skill should be available and the `tomofound` MCP tools should load.

### Step 2 (Gemini CLI) — Restart Gemini CLI

Restart Gemini CLI or open a new session. The `security-scan` skill is installed to `~/.gemini/skills/security-scan/SKILL.md` and should be available for invocation.

### What the installer does

1. Copies the MCP server (`trivy_server.py`) and the scan-rule prompt (`SKILL.md`, plus a `security-scan.md` compatibility copy for older servers) into `~/.tomofound/`
2. Builds the Python virtualenv at `~/.tomofound/venv/` and installs the pinned dependencies
3. Downloads the pinned ATR rule catalog (~59 MB) into `~/.tomofound/catalogs/atr/`, re-verifying the upstream MIT LICENSE first. This runs on **every** installer run, not just the first, and replaces the cached catalog with the pinned version (skipped with `--no-downloads`; if the download fails, the previous cache is kept)
4. Downloads and SHA-256-verifies the pinned Trivy binary (~48 MB archive) into `~/.tomofound/tools/`
5. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json`
6. Installs the Codex skill wrapper into `~/.codex/skills/security-scan/SKILL.md`
7. Registers the `tomofound` MCP server in `~/.codex/config.toml`
8. Installs the Gemini CLI skill wrapper into `~/.gemini/skills/security-scan/SKILL.md`

Steps 2–4 print progress as they go and are **not fatal**: if a download fails the installer says so and finishes, and the scanner runs with reduced coverage until you fetch them later. Skip them entirely with `--no-downloads` on a metered or air-gapped machine.

Doing this work in the installer is deliberate. The alternative — building the venv on Claude Desktop's first server start and fetching Trivy inside a scan — puts long operations behind deadlines nobody controls, which is how a scan ends up quietly matching an eleven-release-old catalog, or a Trivy install times out and caches nothing.

After this, you can forget about installation — just use `/security-scan` in Claude chat, the `security-scan` skill in Codex, or the `security-scan` skill in Gemini CLI.

### Updating

Three things update on **different schedules**. Re-running the installer covers the first, and re-fetches the ATR catalog at its pinned version; the skill registered inside Claude Desktop is a copy you refresh by hand. Missing one is the most common reason a scan silently runs old code or old rules.

| What | How it updates | Automatic? |
|---|---|---|
| tomofound itself (server, prompt source, MCP registration) | re-run the installer | yes, on re-run |
| The skill **registered inside Claude Desktop** | re-add it by hand — see below | **no** |
| The ATR rule catalog | re-run the installer, the plugin's SessionStart hook, or `atr_update` from your assistant — always the **pinned** version | **Only to the pinned version**: on every installer run, and at SessionStart when the cached catalog is not the pin. Never `latest` |

#### 1. tomofound itself

Re-run the same `curl | bash` command. Installation is **idempotent** — re-running is always safe. At the start the installer prints a summary of what it found at `~/.tomofound/` and what it will touch:

- **Refreshed:** server Python modules, the security-scan prompt **at `~/.tomofound/skills/`**, the MCP-server registration in Claude / Codex configs, and the ATR catalog, re-fetched at the pinned version (unless `--no-downloads`).
- **Preserved:** the venv (its `_DEPS_VERSION` marker auto-refreshes deps on the next server start if anything changed), the Trivy binary, and your historical scan reports under `~/.tomofound/reports/`.
- **Reported as orphans:** any `*.py` in `~/.tomofound/server/` that this version no longer ships. The installer doesn't delete them — you decide.

#### 2. Updating the skill inside Claude Desktop (manual)

When you drag `SKILL.md` into **Settings → Customize → Skills**, Claude Desktop takes **its own copy**. The installer cannot reach that copy, so refreshing `~/.tomofound/skills/` changes nothing about what Claude actually runs. Your registered skill keeps working — at whatever version you first added.

To pick up a new version:

1. Re-run the installer (step 1) so `~/.tomofound/skills/security-scan/SKILL.md` is current.
2. Open **Settings → Customize → Skills**, remove the existing `security-scan` entry, and drag the refreshed file back in.
3. Quit Claude fully (**Cmd-Q**) and reopen it.

Codex and Gemini CLI read their skill files from disk each session, so for those the installer alone is enough — restart the client and you're current.

If you only need the checklist and not the slash command, `/tomofound__security_scan` comes from the MCP server directly and is always at the installed version, no re-registration involved.

#### 3. Updating the ATR rule catalog

The catalog only ever moves to the **pinned** ATR release, never to `latest`. It is downloaded in three situations:

- **Installer runs** (`setup.sh`): every run, unless you pass `--no-downloads`. The installer re-fetches the pinned catalog even when the cache already matches.
- **Plugin `SessionStart` hook** (Claude Code plugin): only when the cached catalog is not the pinned version, for example after a tomofound upgrade changed the pin. If the cache already matches, the hook leaves it alone.
- **On request**, with `atr_update`:

```
Call the atr_update MCP tool          (or just ask: "run atr_update")
```

Ask your assistant to run it, or invoke the tool directly. It downloads the pinned ATR release, re-verifies the upstream LICENSE is still MIT before trusting the tarball, and re-parses every rule into `~/.tomofound/catalogs/atr/`. Every download path makes the same LICENSE check.

**Upgrading tomofound does not refresh the catalog by itself.** An upgrade changes which ATR version is *pinned*; the catalog on disk stays put until the next installer run, the next Claude Code session (if you use the plugin), or an `atr_update`. Until then, scans keep matching the rules you downloaded last time — potentially many releases and hundreds of rules behind.

The report header calls this out rather than showing a green tick for a stale catalog:

```
⚠️ Agent Threat Rules (ATR) v3.5.0 (244 rules) — STALE: this build pins
   v4.3.1; run atr_update before trusting these results
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
- **Check it isn't stale.** `atr_status` reports the cached version; if it differs from the pinned one the header shows `STALE` and the scan is matching whatever you downloaded last time. Run `atr_update`. See [Updating](#3-updating-the-atr-rule-catalog).
- Verify the target path exists and contains scannable files by running the `discover_targets` tool.
- Ensure extensions are installed in their standard locations (`~/.claude/`, `~/.codex/`, `~/.gemini/`).

### I upgraded tomofound but nothing changed

Three things update separately — see [Updating](#updating). In order of how often it catches people:

- **The skill in Claude Desktop keeps its own copy.** Re-running the installer refreshes `~/.tomofound/skills/` but not what Claude runs. Remove and re-add the skill under **Settings → Customize → Skills**, then Cmd-Q and reopen. Codex and Gemini CLI don't have this problem — they read from disk each session.
- **The ATR catalog moves only to the pinned release.** A new tomofound version changes which ATR release is *pinned*. Re-run the installer, start a new Claude Code session if you use the plugin, or run `atr_update` to pick it up. Until one of those happens, the rules on disk stay put and the report flags the catalog as STALE.
- **Trivy is reused once installed.** A binary already on `PATH` or in `~/.tomofound/tools/` is used as-is even if this build pins a newer one. The report flags it; delete the binary to let tomofound install the pinned build.

### `/security-scan` says "unknown skill"

The registered skill predates the fix that aligned its declared name with its directory. Re-add it (see above). `/tomofound__security_scan` works meanwhile — that name comes from the MCP server and never changed.

### setup.sh errors

- **"Not macOS"**: tomofound currently supports macOS only. Windows is **not supported yet** (the repo has no `setup.ps1`), and Linux support is planned.
- **Permission denied**: check ownership of `~/.tomofound/` (`ls -la ~/.tomofound`).
- For a clean slate, re-run setup.sh with `--clean` to wipe and recreate the installation directory.

### Uninstall

Remove tomofound the way you installed it. The plugin and `setup.sh` write to different places, so follow the subsection that matches your install. If you used both, do both.

#### Claude Code plugin

Inside Claude Code:

```
/plugin uninstall tomofound@tomofound
```

If you don't need the marketplace any more, remove it too:

```
/plugin marketplace remove tomofound
```

`/plugin uninstall` removes the plugin from Claude Code. It does **not** delete `~/.tomofound/`: the plugin keeps its data in that directory (the same one `setup.sh` uses), not in Claude Code's plugin data directory. So the venv, the Trivy binary, the ATR catalog and your scan reports all survive an uninstall. To remove them as well:

```bash
rm -rf ~/.tomofound
```

Only do this when no other client still uses tomofound. Claude Desktop chat, Codex and Gemini CLI installed through `setup.sh` share the same directory, so leave it in place if you still use any of them.

#### `setup.sh`

`setup.sh` writes to the locations below. Remove the ones you don't want any more.

- **`~/.tomofound/`**: the MCP server, the skill prompts, the venv, `tools/trivy`, `catalogs/atr`, `reports`, and the `venv.lock` / `tools.lock` files. Remove it with `rm -rf ~/.tomofound`, but only when no other client still uses it (see the warning above).
- **Claude Desktop**, two places:
  - `~/Library/Application Support/Claude/claude_desktop_config.json`: delete the `"tomofound"` key under `mcpServers`. Edit the file by hand; it holds other Claude preferences too.
  - **Settings → Customize → Skills**: remove the `security-scan` skill you added.
- **Codex**, two places:
  - Delete the directory `~/.codex/skills/security-scan/`.
  - `~/.codex/config.toml`: delete the whole `[mcp_servers.tomofound]` table. Leave the rest of the file as it is.
- **Gemini CLI**: delete the directory `~/.gemini/skills/security-scan/`. `setup.sh` does not register an MCP server for Gemini CLI, so there is no config to edit.

If you also registered `tomofound` in Claude Code yourself (for example with `claude mcp add`), remove that registration with the commands in [Moving from `setup.sh` to the plugin](#moving-from-setupsh-to-the-plugin-claude-code).

Afterwards, restart the apps you use: quit Claude Desktop fully with **Cmd-Q** and reopen it, and restart Codex or Gemini CLI.

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

**Credential files are never handed to the LLM verbatim.** The `read_file` tool masks `oauth_creds.json`, `credentials.json`, `auth.json`, `.env` and `*.env` / `.env.*` files: JSON keeps its keys and structure with every string/number value replaced by `<redacted:N chars>`, `.env`-style files are not parsed at all and are withheld entirely (`content withheld: .env-style credential file`; dotenv dialects disagree on quoting and escapes, so any line-level masking would leak), a credential `.json` that fails to parse is withheld entirely (`content withheld: unparseable JSON`), and a credential file over 10 MiB is withheld (`content withheld: too large`). Secret detection on those files is done server-side by Trivy, which reads them without returning their contents.

## Risk score

Each scan produces a 0–100 risk score (severity-weighted across all findings) and an install recommendation:

| Score | Recommendation |
|-------|----------------|
| 0 | ✅ Safe |
| 1–15 | 🔵 Caution |
| 16–50 | ⚠️ High Risk |
| 51–100 | 🚫 Avoid |

## How rules work

Detection rules live in `skills/security-scan/SKILL.md` (installed locally to `~/.tomofound/skills/security-scan/SKILL.md`, with a `security-scan.md` compatibility copy beside it until the pinned release catches up). The MCP server loads this file at startup and serves it as the Claude `/security-scan` prompt. Codex uses `integrations/codex/skills/security-scan/SKILL.md` and Gemini CLI uses `integrations/gemini/skills/security-scan/SKILL.md` as lightweight skill wrappers around the same MCP tools. To add a shared scan rule, edit the Claude prompt and the Codex/Gemini wrappers as needed, then re-run the installer.

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
| Python `mcp` SDK | `1.30.0` (exact pin) | [MIT](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE) | https://pypi.org/project/mcp/ | Installed into `~/.tomofound/venv` on first server start by `_bootstrap()` (see `server/trivy_server.py`). Bump the `_PIP_DEPS` list + this table together. |
| Python `PyYAML` | `>=6.0,<7` | [MIT](https://github.com/yaml/pyyaml/blob/main/LICENSE) | https://pypi.org/project/PyYAML/ | Installed alongside `mcp` by `_bootstrap()`. Parses the Agent Threat Rules YAML catalog. |
| Trivy CLI | `0.76.2` (pinned in `server/trivy_server.py:_TRIVY_PIN`) | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | https://github.com/aquasecurity/trivy | Downloaded on first scan from the pinned release tag, verified against Trivy's published sha256 checksums, then cached at `~/.tomofound/tools/trivy`. **Deliberately pinned, not floating-latest**: Trivy's March 2026 supply-chain incident shipped a malicious release with matching checksums — a floating `releases/latest` install cannot survive that attack. Bumping the pin is an explicit, reviewed change. Trivy's CVE *database* still auto-updates independently of the binary version. |
| OSV vulnerability API | API v1 (live) | [Apache-2.0](https://github.com/google/osv.dev/blob/master/LICENSE) (engine); upstream advisory licenses for individual entries | https://osv.dev | Queried by the `check_osv` MCP tool as a fallback when Trivy has no dependency manifest. Findings cite the OSV advisory ID. |
| Agent Threat Rules (ATR) catalog | `v4.3.1` (pinned in `server/atr_catalog.py:ATR_PIN`) | [MIT](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v4.3.1/LICENSE) (SPDX `MIT`; verified at the `v4.3.1` tag: LICENSE sha256 `aaf963e7…c92598`, byte-identical to the previous pin's LICENSE, covers the engine and the `rules/` data we read, no other LICENSE/COPYING file under `rules/`) | https://github.com/Agent-Threat-Rule/agent-threat-rules | Source tarball (~59 MB) downloaded at the pinned tag by `setup.sh` on every run (unless `--no-downloads`), by the plugin's SessionStart hook when the cached catalog is not the pinned version, and by the user-initiated `atr_update` MCP tool; cached at `~/.tomofound/catalogs/atr/` (rules + LICENSE retained per MIT). Never fetches `latest`. Every download re-verifies the upstream LICENSE is still MIT before trusting the tarball, and flags (without refusing) a LICENSE whose hash differs from the reviewed one. We use ATR as a regex pre-filter — findings cite rule IDs (`ATR-YYYY-NNNNN`) and upstream references (OWASP Agentic / MITRE ATLAS / CVE). |
| host Python 3 | `≥3.10` | [PSF License](https://docs.python.org/3/license.html) | macOS system or your own Python install | Required for the bootstrap venv and the server: `mcp` 1.30.0 needs 3.10+, and the server uses `X \| None` annotations at runtime. On macOS, `python3` is a Command Line Tools stub (it prompts for install when the tools are missing), and Apple's bundled Python is older than 3.10, so install a newer Python. |
| host `git` | any recent | [GPL-2.0](https://git-scm.com/about/free-and-open-source) | macOS system | Required only when scanning a `https://github.com/...` URL via `clone_repo`. Used as a CLI subprocess; we do not link git as a library. |
| Python stdlib | ships with host Python | [PSF License](https://docs.python.org/3/license.html) | https://docs.python.org/3/library/ | `ast`, `ipaddress`, `socket`, `subprocess`, `tarfile`, `tempfile`, `urllib`, `zipfile`, etc. |

### Outbound network calls

| URL pattern | Purpose | Who triggers it |
|-------------|---------|-----------------|
| `https://pypi.org/` (wheels from `files.pythonhosted.org`) | `pip install` of the pinned `mcp` SDK and `PyYAML` into `~/.tomofound/venv` | First server start (or the plugin's `--ensure-tools` hook), when the venv is missing or out of date |
| `https://github.com/aquasecurity/trivy/releases/download/v0.76.2/...` | Download the pinned Trivy binary + its published checksums | First scan, when Trivy isn't on `PATH` |
| `https://api.osv.dev/v1/query` | OSV vulnerability lookup (Level-4 fallback when Trivy has no dependency manifest) | The `check_osv` MCP tool |
| `https://github.com/<owner>/<repo>(.git)` | `git clone --depth 1` for pre-install scan of a GitHub URL | The `clone_repo` MCP tool |
| `https://<host>/<path>.zip` | Download a `.zip` for pre-install scan | The `extract_zip` MCP tool — **https only**, refuses private / loopback / link-local / cloud-metadata hosts, re-validates every redirect target |
| `https://raw.githubusercontent.com/rotoyang/tomofound/<release tag>/...` | Installer fetches the server + skill at the pinned tag (`TOMOFOUND_REF`, default the current release; a missing tag fails loudly rather than falling back to `main`) | `setup.sh` only |
| `https://github.com/rotoyang/tomofound` at the release tag (`ref` in `.claude-plugin/marketplace.json`) | Claude Code clones the plugin at the pinned tag | The user's `/plugin marketplace add` / `/plugin install` — performed by Claude Code, not by tomofound code |
| The Trivy URLs above, and the ATR URLs in the two rows below | Same downloads as the installer, run in the background at session start | The plugin's `SessionStart` hook (`--ensure-tools`): Trivy when it is missing, ATR only when the cached catalog is not the pinned version. A no-op once both are in place |
| `https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/v4.3.1/LICENSE` | Re-verify ATR upstream license before trusting a catalog refresh | Every ATR catalog download: `setup.sh`, the `--ensure-tools` hook (only when the cached catalog is not the pinned version), and the `atr_update` MCP tool |
| `https://github.com/Agent-Threat-Rule/agent-threat-rules/archive/refs/tags/v4.3.1.tar.gz` | Download the pinned ATR source tarball | `setup.sh` (every run, unless `--no-downloads`), the `--ensure-tools` hook (only when the cached catalog is not the pinned version), and the `atr_update` MCP tool (on request) |
| `https://api.github.com/repos/Agent-Threat-Rule/agent-threat-rules/releases/latest` | Report whether a newer ATR release exists than our pin (never downloads) | The `catalogs_status` MCP tool — only when called with `check_upstream: true`; local-only by default |
| `codeload.github.com` | 302 redirect destination of the ATR tarball download (`github.com/.../archive/refs/tags/<tag>.tar.gz`) | `setup.sh`, the `--ensure-tools` hook and the `atr_update` MCP tool, via the GitHub redirect |
| `release-assets.githubusercontent.com` | 302 redirect destination of the Trivy release download (`github.com/aquasecurity/trivy/releases/download/...`) | The Trivy download (first scan or the `--ensure-tools` hook), via the GitHub redirect; the binary is still checked against the published sha256 |
| `mirror.gcr.io`, `ghcr.io` | Trivy's default OCI registries for its vulnerability DB, Java DB and checks bundle (`--db-repository`, `--java-db-repository`, `--checks-bundle-repository` defaults) | Connected to by the **Trivy subprocess** during a scan, not by tomofound's own code |

`network.hosts` in `.claude-plugin/plugin.json` discloses all of the hosts above for the plugin. It is informational: Claude Code does not use it to allow or block connections.

### Repository assets

| Asset | Source | Notes |
|-------|--------|-------|
| `server/trivy_server.py` | This repo | The MCP server itself |
| `server/atr_catalog.py` | This repo | ATR catalog pin, download and parsing; imported by `trivy_server.py` at runtime |
| `server/python_analyzer.py` | This repo | AST + taint static analysis |
| `skills/security-scan/SKILL.md` | This repo | Detection rules loaded as an MCP prompt; also the plugin's `/tomofound:security-scan` skill (auto-detected) |
| `integrations/codex/skills/security-scan/SKILL.md` | This repo | Codex-side wrapper around the same MCP tools |
| `integrations/gemini/skills/security-scan/SKILL.md` | This repo | Gemini CLI-side wrapper around the same MCP tools |
| `setup.sh` | This repo | One-shot installer |
| `.claude-plugin/plugin.json` | This repo | Claude Code plugin manifest (name, version, author, MIT license, `network.hosts`). `version` must equal `setup.sh`'s `TOMOFOUND_REF` minus the `v`. `network.hosts` is a disclosure list of the hosts in the outbound table (`github.com`, `api.github.com`, `raw.githubusercontent.com`, `codeload.github.com`, `release-assets.githubusercontent.com`, `api.osv.dev`, `pypi.org`, `files.pythonhosted.org`, `mirror.gcr.io`, `ghcr.io`); Claude Code does not enforce it (it neither allows nor blocks any host). Add a host there whenever a new outbound URL is added |
| `.claude-plugin/marketplace.json` | This repo | Single-plugin marketplace; the plugin `source` is this repo at the `TOMOFOUND_REF` tag, never `main` |
| `.mcp.json` | This repo | Plugin MCP registration: `python3 ${CLAUDE_PLUGIN_ROOT}/server/trivy_server.py` |
| `hooks/hooks.json` | This repo | Plugin `SessionStart` hook: `trivy_server.py --ensure-tools`, async, 600 s timeout |

`tests/test_plugin_packaging.py` fails if the three version pins drift, if the marketplace stops pinning a tag, or if the plugin config contains a hard-coded local path.

No third-party Python wheels are vendored, no binary blobs ship in the repo, and the installer touches only `~/.tomofound/`, `~/Library/Application Support/Claude/claude_desktop_config.json`, (if Codex is selected) `~/.codex/config.toml` + `~/.codex/skills/security-scan/`, and (if Gemini is selected) `~/.gemini/skills/security-scan/`.

The Claude Code plugin writes nothing outside `~/.tomofound/` itself: the venv, ATR catalog, Trivy binary and reports all live there, same as the installer path. Claude Code additionally keeps its own copy of the plugin in its plugin cache; that is Claude Code's bookkeeping, not a tomofound write.

### Attribution

tomofound's scanning pipeline integrates the following independent projects. Each runs under its own license listed above — we use them as documented, attribute them in scan reports, and do not redistribute their data.

- **Trivy** — vulnerability and secret scanning, © [Aqua Security](https://github.com/aquasecurity/trivy), Apache-2.0. Pinned release installed at first scan (checksum-verified); binary lives at `~/.tomofound/tools/trivy`.
- **OSV.dev** — open-source vulnerability database, © [Google](https://github.com/google/osv.dev), Apache-2.0. Queried live as a CVE-fallback source.
- **Model Context Protocol Python SDK** — © [Anthropic, PBC](https://github.com/modelcontextprotocol/python-sdk), MIT. Provides the stdio MCP server runtime our `trivy_server.py` is built on.
- **PyYAML** — © Kirill Simonov and contributors, MIT. Parses the Agent Threat Rules YAML catalog into our internal regex pre-filter.
- **Agent Threat Rules (ATR)** — open detection rule format for AI-agent security threats, © [ATR Contributors](https://github.com/Agent-Threat-Rule/agent-threat-rules), MIT. Pinned to `v4.3.1` (MIT verified at that tag — LICENSE covers the rule data we fetch; fetched on the user's machine, not redistributed); consumed as a regex pre-filter by the `atr_match` MCP tool. Each ATR-sourced finding cites the upstream rule ID (`ATR-YYYY-NNNNN`) and the references the rule defines (OWASP Agentic Top 10, MITRE ATLAS, CVE) — see the rule index at https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/v4.3.1/rules.

When tomofound integrates additional rule or threat-intel catalogs (e.g. Bumblebee), each will be added to this list with its license, upstream URL, and the version we pin. See `docs/catalog-architecture.md` (local design notes) for the license-compliance protocol we follow before integrating any new source.
