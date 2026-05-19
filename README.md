# tomofound

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini, and OpenAI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, and prompt injection — before or after installation.

## Installation

```bash
/install https://github.com/rotoyang/tomofound
```

## Usage

```bash
# Scan all installed AI tool extensions
/security-scan

# Scan only Claude Code plugins
/security-scan --target claude

# Scan only Gemini configuration
/security-scan --target gemini

# Pre-installation scan — local file or directory
/security-scan ~/Downloads/suspicious-plugin.zip
/security-scan ~/Downloads/plugin-dir/

# Pre-installation scan — GitHub repository
/security-scan https://github.com/user/plugin
```

## What it scans

| Item | Method | Detects |
|------|--------|---------|
| Plugins & connectors (`.ts` `.js` `.py` `.go` `.rs` `.sh`) | Trivy + LLM | Secrets, backdoors, data exfiltration, CVEs, supply-chain issues |
| Skills (`.md`) | LLM | Prompt injection, behaviour override, social engineering |
| Config files (`settings.json`, `oauth_creds.json`) | LLM | Plaintext credentials, overly permissive settings |

Trivy is installed automatically if not already present — no manual setup required.

## How rules work

Detection rules are prompt instructions inside `skills/security-scan/security-scan.md`. To add a new rule, edit that file and add a bullet point under the relevant category. No code to compile or deploy.

## Reports

Scan reports are saved to `~/.claude/security-reports/YYYY-MM-DD-HH-MM.md`.
