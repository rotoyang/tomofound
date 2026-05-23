# tomofound

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini CLI, and Codex CLI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, and prompt injection — before or after installation.

## Requirements

- macOS
- [Claude Desktop App](https://claude.ai/download)
- Python 3 (preinstalled on macOS)
- `git` on PATH (for pre-install scans of GitHub URLs)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

Then quit Claude Desktop App fully (Cmd-Q) and reopen it. Type `/` in any chat — `/tomofound__security_scan` should appear in the menu.

The installer:
1. Copies the MCP server and prompt source into `~/.tomofound/`
2. Registers the `tomofound` MCP server in `~/Library/Application Support/Claude/claude_desktop_config.json`

### Updating

Re-run the same `curl | bash` command. Existing configuration is preserved; only the server and prompt source are refreshed.

## Usage

```
# Scan all installed AI tool extensions
/tomofound__security_scan

# Scan only Claude Code plugins
/tomofound__security_scan --target claude

# Scan only Gemini configuration
/tomofound__security_scan --target gemini

# Scan only Codex configuration
/tomofound__security_scan --target openai

# Pre-installation scan — local directory
/tomofound__security_scan ~/Downloads/plugin-dir/

# Pre-installation scan — GitHub repository
/tomofound__security_scan https://github.com/user/plugin
```

## What it scans

| Item | Method | Detects |
|------|--------|---------|
| Plugins & connectors (`.ts` `.js` `.py` `.go` `.rs` `.sh`) | Trivy + LLM | Secrets, backdoors, data exfiltration, CVEs, supply-chain issues |
| Skills, agents, prompts (`.md` `AGENTS.md`) | LLM | Prompt injection, behaviour override, social engineering |
| Config files (`settings.json`, `oauth_creds.json`, `auth.json`, `config.toml`) | LLM | Plaintext credentials, overly permissive settings |

Trivy is auto-installed to `~/.tomofound/tools/trivy` on first scan if not already on PATH.

## How rules work

Detection rules live in `skills/security-scan/security-scan.md` (installed to `~/.tomofound/skills/security-scan/security-scan.md`). The MCP server loads this file at startup and serves it as the `/tomofound__security_scan` prompt. To add a rule, edit the file and re-run the installer — no code changes required.

## Reports

Scan reports are saved to `~/.tomofound/reports/YYYY-MM-DD-HH-MM.md`.
