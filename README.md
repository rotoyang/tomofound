# tomofound

Security scanner for AI tool plugins, skills, and connectors.

Scans extensions installed for Claude Code, Gemini CLI, and Codex CLI for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, prompt injection, MCP tool poisoning, and memory poisoning — before or after installation. Combines Trivy CVE/secret scanning, Python AST + taint-tracking static analysis, and optional LLM semantic review, then emits a 0–100 risk score with an install recommendation.

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

# Pre-install — scan a .zip archive (local path or https URL)
/security_scan ~/Downloads/plugin.zip
/security_scan https://example.com/plugin.zip
```

### Codex

Invoke the `security-scan` skill when asking Codex to audit installed extensions, a local path, a `.zip` archive, or a public GitHub repository. Codex uses the same Tomofound MCP server and writes reports to the same `~/.tomofound/reports/` directory.

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

Detection rules live in `skills/security-scan/security-scan.md` (installed locally to `~/.tomofound/skills/security-scan/security-scan.md`). The MCP server loads this file at startup and serves it as the Claude `/security_scan` prompt. Codex uses `integrations/codex/skills/security-scan/SKILL.md` as a lightweight skill wrapper around the same MCP tools. To add a shared scan rule, edit the Claude prompt and Codex wrapper as needed, then re-run the installer.

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
| Python `mcp` SDK | `1.28.0` (exact pin) | [MIT](https://github.com/modelcontextprotocol/python-sdk/blob/main/LICENSE) | https://pypi.org/project/mcp/ | Installed into `~/.tomofound/venv` on first server start by `_bootstrap()` (see `server/trivy_server.py`). Bump the `_PIP_DEPS` list + this table together. |
| Python `PyYAML` | `>=6.0,<7` | [MIT](https://github.com/yaml/pyyaml/blob/main/LICENSE) | https://pypi.org/project/PyYAML/ | Installed alongside `mcp` by `_bootstrap()`. Parses the Agent Threat Rules YAML catalog. |
| Trivy CLI | auto-installed *latest stable* | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | https://github.com/aquasecurity/trivy | Resolved via `https://api.github.com/repos/aquasecurity/trivy/releases/latest` on first scan, then cached at `~/.tomofound/tools/trivy`. Not pinned — Trivy ships CVE database auto-updates anyway, so pinning the binary alone wouldn't make the scan reproducible. |
| OSV vulnerability API | API v1 (live) | [Apache-2.0](https://github.com/google/osv.dev/blob/master/LICENSE) (engine); upstream advisory licenses for individual entries | https://osv.dev | Queried by the `check_osv` MCP tool as a fallback when Trivy has no dependency manifest. Findings cite the OSV advisory ID. |
| Agent Threat Rules (ATR) catalog | `v3.5.0` (pinned in `server/atr_catalog.py:ATR_PIN`) | [MIT](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v3.5.0/LICENSE) | https://github.com/Agent-Threat-Rule/agent-threat-rules | Source tarball downloaded by the user-initiated `atr_update` MCP tool, then cached at `~/.tomofound/catalogs/atr/` (rules + LICENSE retained per MIT). Never auto-updated; `atr_update` re-verifies the upstream LICENSE is still MIT before trusting a new tarball. We use ATR as a regex pre-filter — findings cite rule IDs (`ATR-YYYY-NNNNN`) and upstream references (OWASP Agentic / MITRE ATLAS / CVE). |
| host Python 3 | `≥3.9` | [PSF License](https://docs.python.org/3/license.html) | macOS system | Required for the bootstrap venv. Preinstalled on macOS. |
| host `git` | any recent | [GPL-2.0](https://git-scm.com/about/free-and-open-source) | macOS system | Required only when scanning a `https://github.com/...` URL via `clone_repo`. Used as a CLI subprocess; we do not link git as a library. |
| Python stdlib | ships with host Python | [PSF License](https://docs.python.org/3/license.html) | https://docs.python.org/3/library/ | `ast`, `ipaddress`, `socket`, `subprocess`, `tarfile`, `tempfile`, `urllib`, `zipfile`, etc. |

### Outbound network calls

| URL pattern | Purpose | Who triggers it |
|-------------|---------|-----------------|
| `https://api.github.com/repos/aquasecurity/trivy/releases/latest` | Look up Trivy version to download | First scan, when Trivy isn't on `PATH` |
| `https://github.com/aquasecurity/trivy/releases/download/...` | Download the Trivy binary | First scan, after the lookup above |
| `https://api.osv.dev/v1/query` | OSV vulnerability lookup (Level-4 fallback when Trivy has no dependency manifest) | The `check_osv` MCP tool |
| `https://github.com/<owner>/<repo>(.git)` | `git clone --depth 1` for pre-install scan of a GitHub URL | The `clone_repo` MCP tool |
| `https://<host>/<path>.zip` | Download a `.zip` for pre-install scan | The `extract_zip` MCP tool — **https only**, refuses private / loopback / link-local / cloud-metadata hosts, re-validates every redirect target |
| `https://raw.githubusercontent.com/rotoyang/tomofound/main/...` | Installer fetches its own source | `setup.sh` only |
| `https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/v3.5.0/LICENSE` | Re-verify ATR upstream license before trusting a catalog refresh | The `atr_update` MCP tool |
| `https://github.com/Agent-Threat-Rule/agent-threat-rules/archive/refs/tags/v3.5.0.tar.gz` | Download the pinned ATR source tarball | The `atr_update` MCP tool — user-initiated only, never auto-run |

### Repository assets

| Asset | Source | Notes |
|-------|--------|-------|
| `server/trivy_server.py` | This repo | The MCP server itself |
| `server/python_analyzer.py` | This repo | AST + taint static analysis |
| `skills/security-scan/security-scan.md` | This repo | Detection rules loaded as an MCP prompt |
| `integrations/codex/skills/security-scan/SKILL.md` | This repo | Codex-side wrapper around the same MCP tools |
| `setup.sh` | This repo | One-shot installer |

No third-party Python wheels are vendored, no binary blobs ship in the repo, and the installer touches only `~/.tomofound/`, `~/Library/Application Support/Claude/claude_desktop_config.json`, and (if Codex is selected) `~/.codex/config.toml` + `~/.codex/skills/security-scan/`.

### Attribution

tomofound's scanning pipeline integrates the following independent projects. Each runs under its own license listed above — we use them as documented, attribute them in scan reports, and do not redistribute their data.

- **Trivy** — vulnerability and secret scanning, © [Aqua Security](https://github.com/aquasecurity/trivy), Apache-2.0. Auto-installed at first scan; binary lives at `~/.tomofound/tools/trivy`.
- **OSV.dev** — open-source vulnerability database, © [Google](https://github.com/google/osv.dev), Apache-2.0. Queried live as a CVE-fallback source.
- **Model Context Protocol Python SDK** — © [Anthropic, PBC](https://github.com/modelcontextprotocol/python-sdk), MIT. Provides the stdio MCP server runtime our `trivy_server.py` is built on.
- **PyYAML** — © Kirill Simonov and contributors, MIT. Parses the Agent Threat Rules YAML catalog into our internal regex pre-filter.
- **Agent Threat Rules (ATR)** — open detection rule format for AI-agent security threats, © [ATR Contributors](https://github.com/Agent-Threat-Rule/agent-threat-rules), MIT. Pinned to `v3.5.0`; consumed as a regex pre-filter by the `atr_match` MCP tool. Each ATR-sourced finding cites the upstream rule ID (`ATR-YYYY-NNNNN`) and the references the rule defines (OWASP Agentic Top 10, MITRE ATLAS, CVE) — see the rule index at https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/v3.5.0/rules.

When tomofound integrates additional rule or threat-intel catalogs (e.g. Bumblebee), each will be added to this list with its license, upstream URL, and the version we pin. See `docs/catalog-architecture.md` (local design notes) for the license-compliance protocol we follow before integrating any new source.
