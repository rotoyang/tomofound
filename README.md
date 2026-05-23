# tomofound

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini CLI, and Codex CLI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, and prompt injection — before or after installation.

## How it works

tomofound is **install once, then use it from Claude or Codex**:

1. Run `setup.sh` manually one time to install the shared MCP server and scan rules.
2. The installer registers Tomofound with Claude and Codex.
3. From then on, invoke `/security_scan` in Claude or the `security-scan` skill in Codex — no further setup, no per-scan installation, no Trivy install (auto-handled on first scan).

## Requirements

- macOS
- [Claude desktop app](https://claude.ai/download) (for Claude usage)
- Codex (for Codex usage)
- Python 3 (preinstalled on macOS)
- `git` on PATH (only needed when you pass a `https://github.com/...` URL)

## Installation (one-time)

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

By default this configures both Claude and Codex.

```bash
# Claude only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --claude

# Codex only
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash -s -- --codex
```

Then restart the app you configured:

- Claude: quit fully (Cmd-Q) and reopen it. Verify by typing `/` in any chat — `/security_scan` should appear in the slash menu.
- Codex: restart Codex or open a new thread. The `security-scan` skill should be available and the `tomofound` MCP tools should load.

What the installer does:

1. Copies the MCP server (`trivy_server.py`) and the Claude scan-rule prompt (`security-scan.md`) into `~/.tomofound/`
2. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Installs the Codex skill wrapper into `~/.codex/skills/security-scan/SKILL.md`
4. Registers the `tomofound` MCP server in `~/.codex/config.toml`

After this, you can forget about installation — just use the configured Claude or Codex entry point.

### Updating

Re-run the same `curl | bash` command. Existing configuration is preserved; only the server file and prompt source are refreshed.

### Uninstall

```bash
# Remove server, reports, and auto-installed Trivy binary
rm -rf ~/.tomofound
```

Then remove the `"tomofound"` key under `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json` (edit by hand — the file holds other Claude preferences too).

## Usage

Once installed, the scan entry point is always available in configured apps. No need to re-run `setup.sh` between scans.

### Claude

```
# Scan everything installed on this Mac
/security_scan

# Scan only Claude Code plugins / skills / agents / commands
/security_scan --target claude

# Scan only Gemini CLI config + extensions
/security_scan --target gemini

# Scan only Codex CLI config + prompts
/security_scan --target openai

# Pre-install — scan a local directory
/security_scan ~/Downloads/plugin-dir/

# Pre-install — scan a public GitHub repo
/security_scan https://github.com/user/plugin
```

### Codex

Invoke the `security-scan` skill when asking Codex to audit installed extensions, a local path, or a public GitHub repository. Codex uses the same Tomofound MCP server and writes reports to the same `~/.tomofound/reports/` directory.

Each invocation writes a markdown report to `~/.tomofound/reports/YYYY-MM-DD-HH-MM.md`.

## What it scans

| Item | Method | Detects |
|------|--------|---------|
| Plugins & connectors (`.ts` `.js` `.py` `.go` `.rs` `.sh`) | Trivy + LLM | Secrets, backdoors, data exfiltration, CVEs, supply-chain issues |
| Skills, agents, prompts (`.md`, `AGENTS.md`) | LLM | Prompt injection, behaviour override, social engineering |
| Config files (`settings.json`, `oauth_creds.json`, `auth.json`, `config.toml`) | LLM | Plaintext credentials, overly permissive settings |

Trivy is auto-installed to `~/.tomofound/tools/trivy` on first scan if it isn't already on `PATH`.

## How rules work

Detection rules live in `skills/security-scan/security-scan.md` (installed locally to `~/.tomofound/skills/security-scan/security-scan.md`). The MCP server loads this file at startup and serves it as the Claude `/security_scan` prompt. Codex uses `integrations/codex/skills/security-scan/SKILL.md` as a lightweight skill wrapper around the same MCP tools. To add a shared scan rule, edit the Claude prompt and Codex wrapper as needed, then re-run the installer.

## Reports

Scan reports are saved to `~/.tomofound/reports/YYYY-MM-DD-HH-MM.md`.
