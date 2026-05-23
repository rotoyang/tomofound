# tomofound

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini CLI, and Codex CLI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, and prompt injection — before or after installation.

## How it works

tomofound is **install once, then use slash commands**:

1. Run `setup.sh` manually one time to install the MCP server and register it with Claude
2. From then on, invoke `/tomofound__security_scan` in any Claude session — no further setup, no per-scan installation, no Trivy install (auto-handled on first scan)

## Requirements

- macOS
- [Claude desktop app](https://claude.ai/download) (the unified app — includes chat and Claude Code surfaces)
- Python 3 (preinstalled on macOS)
- `git` on PATH (only needed when you pass a `https://github.com/...` URL)

## Installation (one-time)

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

Then quit Claude fully (Cmd-Q) and reopen it. Verify by typing `/` in any chat — `/tomofound__security_scan` should appear in the slash menu.

What the installer does:

1. Copies the MCP server (`trivy_server.py`) and the scan-rule prompt (`security-scan.md`) into `~/.tomofound/`
2. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json`

After this, you can forget about installation — just use the slash command.

### Updating

Re-run the same `curl | bash` command. Existing configuration is preserved; only the server file and prompt source are refreshed.

### Uninstall

```bash
# Remove server, reports, and auto-installed Trivy binary
rm -rf ~/.tomofound
```

Then remove the `"tomofound"` key under `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json` (edit by hand — the file holds other Claude preferences too).

## Usage

Once installed, the slash command is always available in any Claude session. No need to re-run `setup.sh` between scans.

```
# Scan everything installed on this Mac
/tomofound__security_scan

# Scan only Claude Code plugins / skills / agents / commands
/tomofound__security_scan --target claude

# Scan only Gemini CLI config + extensions
/tomofound__security_scan --target gemini

# Scan only Codex CLI config + prompts
/tomofound__security_scan --target openai

# Pre-install — scan a local directory
/tomofound__security_scan ~/Downloads/plugin-dir/

# Pre-install — scan a public GitHub repo
/tomofound__security_scan https://github.com/user/plugin
```

Each invocation writes a markdown report to `~/.tomofound/reports/YYYY-MM-DD-HH-MM.md`.

## What it scans

| Item | Method | Detects |
|------|--------|---------|
| Plugins & connectors (`.ts` `.js` `.py` `.go` `.rs` `.sh`) | Trivy + LLM | Secrets, backdoors, data exfiltration, CVEs, supply-chain issues |
| Skills, agents, prompts (`.md`, `AGENTS.md`) | LLM | Prompt injection, behaviour override, social engineering |
| Config files (`settings.json`, `oauth_creds.json`, `auth.json`, `config.toml`) | LLM | Plaintext credentials, overly permissive settings |

Trivy is auto-installed to `~/.tomofound/tools/trivy` on first scan if it isn't already on `PATH`.

## How rules work

Detection rules live in `skills/security-scan/security-scan.md` (installed locally to `~/.tomofound/skills/security-scan/security-scan.md`). The MCP server loads this file at startup and serves it as the `/tomofound__security_scan` prompt. To add a rule, edit that file in this repo, then re-run the installer — no code changes required.

## Reports

Scan reports are saved to `~/.tomofound/reports/YYYY-MM-DD-HH-MM.md`.
