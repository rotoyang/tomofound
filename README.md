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

1. Run `setup.sh` (macOS) or `setup.ps1` (Windows) one time to install the MCP server and scan-rule prompt.
2. Add the scan-rule prompt as a **Skill** in Claude Desktop App (one-time drag-and-drop).
3. From then on, type `/security-scan` in any Claude **chat** to scan — no further setup, no per-scan installation, no Trivy install (auto-handled on first scan).

## Requirements

- macOS, or Windows 10/11
- [Claude desktop app](https://claude.ai/download) (for Claude usage)
- Codex (for Codex usage)
- [Gemini CLI](https://github.com/google-gemini/gemini-cli) (for Gemini CLI usage)
- Python 3 (preinstalled on macOS). On **Windows**, a real Python **3.10+** is required — install with `winget install Python.Python.3.12` if you don't have one. The Microsoft Store "python" alias stub does **not** count (see [Troubleshooting](#windows-python-is-not-recognized--the-microsoft-store-opens)).
- `git` on PATH (only needed when you pass a `https://github.com/...` URL)

## Installation (one-time)

### Step 1 — Run the installer

#### macOS

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

By default this configures Claude, Codex, and Gemini CLI.

```bash
# Claude only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --claude

# Codex only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --codex

# Gemini CLI only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --gemini
```

#### Windows

Open PowerShell (Windows PowerShell 5.1 or PowerShell 7 both work) and run:

```powershell
irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1 | iex
```

By default this configures Claude, Codex, and Gemini CLI. To pass flags to the remote one-liner, invoke it as a script block:

```powershell
# Claude only
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1))) -Claude

# Codex only
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1))) -Codex

# Gemini CLI only
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1))) -Gemini
```

From a cloned repo, run it directly (it then copies your local working-tree files instead of downloading):

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1          # or: .\setup.ps1 -Claude, -Codex, -Gemini, -Clean
```

### Step 2 — Register the skill in Claude Desktop App

1. Open Claude Desktop App.
2. Open **Settings → Customize → Skills**.
3. Drag `~/.tomofound/skills/security-scan/security-scan.md` (Windows: `%USERPROFILE%\.tomofound\skills\security-scan\security-scan.md`) into the Skills list.
4. Quit Claude fully (**Cmd-Q**) and reopen it.
5. Verify: type `/` in any **chat** — `/security-scan` should appear in the slash menu.

### Step 2 (Codex) — Restart Codex

Restart Codex or open a new thread. The `security-scan` skill should be available and the `tomofound` MCP tools should load.

### Step 2 (Gemini CLI) — Restart Gemini CLI

Restart Gemini CLI or open a new session. The `security-scan` skill is installed to `~/.gemini/skills/security-scan/SKILL.md` and should be available for invocation.

### What the installer does

1. Copies the MCP server (`trivy_server.py`) and the scan-rule prompt (`security-scan.md`) into `~/.tomofound/` (Windows: `%USERPROFILE%\.tomofound\`)
2. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json` (Windows: `%APPDATA%\Claude\claude_desktop_config.json`), merging into the existing JSON so other MCP servers are preserved
3. Installs the Codex skill wrapper into `~/.codex/skills/security-scan/SKILL.md`
4. Registers the `tomofound` MCP server in `~/.codex/config.toml`
5. Installs the Gemini CLI skill wrapper into `~/.gemini/skills/security-scan/SKILL.md`

On Windows, `setup.ps1` additionally verifies that a real CPython 3.10+ exists (via the `py -3` launcher, then `python` on PATH — the Microsoft Store alias stub is detected and rejected) and points the MCP server entries at that interpreter.

After this, you can forget about installation — just use `/security-scan` in Claude chat, the `security-scan` skill in Codex, or the `security-scan` skill in Gemini CLI.

### Updating

Re-run the same `curl | bash` command (Windows: the same `irm … | iex` command). Installation is **idempotent** — re-running is always safe. At the start the installer prints a summary of what it found at `~/.tomofound/` and what it will touch:

- **Refreshed:** server Python modules, the security-scan prompt, the MCP-server registration in Claude / Codex configs.
- **Preserved:** the venv (its `_DEPS_VERSION` marker auto-refreshes deps on the next server start if anything changed), cached ATR catalogs, the Trivy binary, and your historical scan reports under `~/.tomofound/reports/`.
- **Reported as orphans:** any `*.py` in `~/.tomofound/server/` that this version no longer ships. The installer doesn't delete them — you decide.

If you want a genuinely fresh install (e.g. clearing reports), use `--clean`:

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --clean
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.ps1))) -Clean
```

`--clean` / `-Clean` wipes the entire `~/.tomofound/` directory after a 5-second confirm window. The MCP server registration in `claude_desktop_config.json` / `~/.codex/config.toml` is re-written either way.

## Troubleshooting

### MCP server won't start / dies immediately

- Verify Python 3.10+: `~/.tomofound/venv/bin/python --version`
- Check the MCP SDK is installed: `~/.tomofound/venv/bin/pip list | grep -i mcp`
- Re-run `setup.sh` to refresh server files and let the bootstrap reinstall dependencies on next start.

### Trivy download fails / times out

- Check network connectivity and proxy settings — the installer fetches Trivy from `github.com`.
- Install Trivy manually (`brew install trivy` or download from [GitHub releases](https://github.com/aquasecurity/trivy/releases)) and ensure it is on `PATH`.
- If the SHA-256 verification fails, retry the download; persistent failures suggest a network integrity issue (transparent proxy, captive portal).

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
- Verify the target path exists and contains scannable files by running the `discover_targets` tool.
- Ensure extensions are installed in their standard locations (`~/.claude/`, `~/.codex/`, `~/.gemini/`).

### setup.sh errors

- **"Not macOS"**: `setup.sh` supports macOS only — on Windows use `setup.ps1` instead; Linux support is planned.
- **Permission denied**: check ownership of `~/.tomofound/` (`ls -la ~/.tomofound`).
- For a clean slate, re-run setup.sh with `--clean` to wipe and recreate the installation directory.

### Windows: `python` is not recognized / the Microsoft Store opens

Stock Windows 10/11 ships a fake `python.exe` under `%LOCALAPPDATA%\Microsoft\WindowsApps` — an "App execution alias" stub that just opens the Microsoft Store. `setup.ps1` detects and rejects it (it probes each candidate interpreter and only accepts a real CPython 3.10+, preferring the `py -3` launcher). If the installer reports no usable Python:

1. Install real Python: `winget install Python.Python.3.12`
2. Open a **new** terminal window (PATH changes don't apply to already-open ones) and re-run the installer.
3. Optionally disable the stub under **Settings → Apps → Advanced app settings → App execution aliases** (turn off both `python.exe` and `python3.exe`).

### Windows: "running scripts is disabled on this system"

PowerShell's execution policy blocks running a locally saved `setup.ps1`. Allow it for the current session only (no permanent policy change):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup.ps1
```

or run `powershell -ExecutionPolicy Bypass -File .\setup.ps1`. The `irm … | iex` one-liner is not affected by execution policy.

### Windows: path-too-long errors during a scan

Deeply nested `node_modules` trees in scanned extensions can exceed Windows' legacy 260-character path limit. Enable long paths once (requires admin), then reboot:

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1
```

### Windows: where is the Claude Desktop config?

On Windows, Claude Desktop reads `%APPDATA%\Claude\claude_desktop_config.json` (typically `C:\Users\<you>\AppData\Roaming\Claude\claude_desktop_config.json`). `setup.ps1` merges the `tomofound` entry into that file, preserving any other MCP servers you have registered. Open it quickly with:

```powershell
notepad $env:APPDATA\Claude\claude_desktop_config.json
```

### Uninstall

```bash
# Remove server, reports, and auto-installed Trivy binary
rm -rf ~/.tomofound
```

```powershell
# Windows
Remove-Item -Recurse -Force $HOME\.tomofound
```

Then:

1. In Claude Desktop App, open **Settings → Customize → Skills** and remove `security-scan`.
2. Remove the `"tomofound"` key under `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json` (Windows: `%APPDATA%\Claude\claude_desktop_config.json`) — edit by hand, the file holds other Claude preferences too.

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
| Agent Threat Rules (ATR) catalog | `v3.5.4` (pinned in `server/atr_catalog.py:ATR_PIN`) | [MIT](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v3.5.4/LICENSE) | https://github.com/Agent-Threat-Rule/agent-threat-rules | Source tarball downloaded by the user-initiated `atr_update` MCP tool, then cached at `~/.tomofound/catalogs/atr/` (rules + LICENSE retained per MIT). Never auto-updated; `atr_update` re-verifies the upstream LICENSE is still MIT before trusting a new tarball. We use ATR as a regex pre-filter — findings cite rule IDs (`ATR-YYYY-NNNNN`) and upstream references (OWASP Agentic / MITRE ATLAS / CVE). |
| host Python 3 | `≥3.9` (macOS) / `≥3.10` (Windows, enforced by `setup.ps1`) | [PSF License](https://docs.python.org/3/license.html) | macOS system / user-installed on Windows | Required for the bootstrap venv. Preinstalled on macOS; on Windows install via `winget install Python.Python.3.12`. |
| host `git` | any recent | [GPL-2.0](https://git-scm.com/about/free-and-open-source) | macOS system | Required only when scanning a `https://github.com/...` URL via `clone_repo`. Used as a CLI subprocess; we do not link git as a library. |
| Python stdlib | ships with host Python | [PSF License](https://docs.python.org/3/license.html) | https://docs.python.org/3/library/ | `ast`, `ipaddress`, `socket`, `subprocess`, `tarfile`, `tempfile`, `urllib`, `zipfile`, etc. |

### Outbound network calls

| URL pattern | Purpose | Who triggers it |
|-------------|---------|-----------------|
| `https://github.com/aquasecurity/trivy/releases/download/v0.72.0/...` | Download the pinned Trivy binary + its published checksums | First scan, when Trivy isn't on `PATH` |
| `https://api.osv.dev/v1/query` | OSV vulnerability lookup (Level-4 fallback when Trivy has no dependency manifest) | The `check_osv` MCP tool |
| `https://github.com/<owner>/<repo>(.git)` | `git clone --depth 1` for pre-install scan of a GitHub URL | The `clone_repo` MCP tool |
| `https://<host>/<path>.zip` | Download a `.zip` for pre-install scan | The `extract_zip` MCP tool — **https only**, refuses private / loopback / link-local / cloud-metadata hosts, re-validates every redirect target |
| `https://raw.githubusercontent.com/rotoyang/tomofound/main/...` | Installer fetches its own source | `setup.sh` / `setup.ps1` only (`setup.ps1` skips the download and copies local files when run from a cloned repo) |
| `https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/v3.5.4/LICENSE` | Re-verify ATR upstream license before trusting a catalog refresh | The `atr_update` MCP tool |
| `https://github.com/Agent-Threat-Rule/agent-threat-rules/archive/refs/tags/v3.5.4.tar.gz` | Download the pinned ATR source tarball | The `atr_update` MCP tool — user-initiated only, never auto-run |
| `https://api.github.com/repos/Agent-Threat-Rule/agent-threat-rules/releases/latest` | Report whether a newer ATR release exists than our pin (never downloads) | The `catalogs_status` MCP tool — only when called with `check_upstream: true`; local-only by default |

### Repository assets

| Asset | Source | Notes |
|-------|--------|-------|
| `server/trivy_server.py` | This repo | The MCP server itself |
| `server/python_analyzer.py` | This repo | AST + taint static analysis |
| `server/atr_catalog.py` | This repo | ATR catalog download, pinning, and regex pre-filter |
| `skills/security-scan/security-scan.md` | This repo | Detection rules loaded as an MCP prompt |
| `integrations/codex/skills/security-scan/SKILL.md` | This repo | Codex-side wrapper around the same MCP tools |
| `integrations/gemini/skills/security-scan/SKILL.md` | This repo | Gemini CLI-side wrapper around the same MCP tools |
| `setup.sh` | This repo | One-shot installer (macOS) |
| `setup.ps1` | This repo | One-shot installer (Windows, PowerShell 5.1+) |

No third-party Python wheels are vendored, no binary blobs ship in the repo, and the installer touches only `~/.tomofound/`, `~/Library/Application Support/Claude/claude_desktop_config.json`, (if Codex is selected) `~/.codex/config.toml` + `~/.codex/skills/security-scan/`, and (if Gemini is selected) `~/.gemini/skills/security-scan/`. On Windows the equivalent set is `%USERPROFILE%\.tomofound\`, `%APPDATA%\Claude\claude_desktop_config.json`, `%USERPROFILE%\.codex\config.toml` + `%USERPROFILE%\.codex\skills\security-scan\`, and `%USERPROFILE%\.gemini\skills\security-scan\`.

### Attribution

tomofound's scanning pipeline integrates the following independent projects. Each runs under its own license listed above — we use them as documented, attribute them in scan reports, and do not redistribute their data.

- **Trivy** — vulnerability and secret scanning, © [Aqua Security](https://github.com/aquasecurity/trivy), Apache-2.0. Pinned release installed at first scan (checksum-verified); binary lives at `~/.tomofound/tools/trivy`.
- **OSV.dev** — open-source vulnerability database, © [Google](https://github.com/google/osv.dev), Apache-2.0. Queried live as a CVE-fallback source.
- **Model Context Protocol Python SDK** — © [Anthropic, PBC](https://github.com/modelcontextprotocol/python-sdk), MIT. Provides the stdio MCP server runtime our `trivy_server.py` is built on.
- **PyYAML** — © Kirill Simonov and contributors, MIT. Parses the Agent Threat Rules YAML catalog into our internal regex pre-filter.
- **Agent Threat Rules (ATR)** — open detection rule format for AI-agent security threats, © [ATR Contributors](https://github.com/Agent-Threat-Rule/agent-threat-rules), MIT. Pinned to `v3.5.4`; consumed as a regex pre-filter by the `atr_match` MCP tool. Each ATR-sourced finding cites the upstream rule ID (`ATR-YYYY-NNNNN`) and the references the rule defines (OWASP Agentic Top 10, MITRE ATLAS, CVE) — see the rule index at https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/v3.5.4/rules.

When tomofound integrates additional rule or threat-intel catalogs (e.g. Bumblebee), each will be added to this list with its license, upstream URL, and the version we pin. See `docs/catalog-architecture.md` (local design notes) for the license-compliance protocol we follow before integrating any new source.
