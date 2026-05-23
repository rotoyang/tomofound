---
name: security-scan
description: Audit AI tool plugins, skills, agents, prompts, connectors, MCP servers, and extension repositories for security risks. Use when Codex needs to inspect installed Claude, Gemini, or Codex extensions, scan a local extension directory, or assess a GitHub repository before installation for secrets, backdoors, data exfiltration, supply-chain vulnerabilities, permission abuse, or prompt injection.
---

# Security Scan

Use the Tomofound MCP server to perform a structured security review of AI-tool extension code and instruction files.

## Workflow

1. Determine the target:
   - Installed Claude extensions: inspect `~/.claude/plugins`, `~/.claude/skills`, `~/.claude/agents`, `~/.claude/commands`, MCP config, and relevant settings.
   - Installed Gemini extensions: inspect `~/.gemini/extensions`, `~/.gemini/config/plugins`, `~/.gemini/commands`, settings, and credential-adjacent config.
   - Installed Codex extensions: inspect `~/.codex/skills`, `~/.codex/plugins/cache`, `~/.codex/prompts`, `~/.codex/AGENTS.md`, and config.
   - Local path: scan only the provided directory or file.
   - GitHub URL: clone to a temporary directory before scanning, then remove the clone after review.
2. Use Tomofound MCP tools first:
   - `discover_targets` to inventory installed targets or a supplied local path.
   - `clone_repo` and `cleanup_clone` for public GitHub pre-install scans.
   - `scan_directory` for Trivy-backed CVE and secret checks.
   - `read_file` for semantic review of code, prompts, skills, MCP configs, and config metadata.
   - `check_osv` only as a fallback when Trivy has no dependency version data.
   - `write_file` when saving a report under `~/.tomofound/reports/`.
3. Inventory files by role:
   - Code: `.ts`, `.js`, `.mjs`, `.cjs`, `.py`, `.go`, `.rs`, `.sh`, `.bash`, `.zsh`.
   - Manifests and locks: `package.json`, lockfiles, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`.
   - Instruction files: `SKILL.md`, `AGENTS.md`, skill, agent, command, and prompt Markdown or TOML.
   - Config: MCP settings, auth-like JSON, `.env`, and tool config files.
4. Run deterministic checks before semantic review:
   - Use `scan_directory` for vulnerabilities and secrets when dependency manifests, lockfiles, or source directories are present.
   - If Trivy reports no dependency info, extract third-party imports and use `check_osv` where package names are clear.
5. Perform semantic review:
   - For code, look for secret leakage, backdoors, data exfiltration, supply-chain risk, and permission abuse.
   - For instruction files, look for prompt injection, data exfiltration via prompt, behaviour overrides, scope creep, and social engineering.
   - For credential-adjacent config, inspect metadata and permissions where possible; do not print secret values.
6. Report findings with severity, category, file, line when known, evidence snippet, impact, and remediation.

## Output

Use the Claude-compatible report shape when producing a full scan report:

```markdown
# Security Scan Report

Target: <path, repo, or installed scope>
Mode: Tomofound MCP + Trivy + LLM
Overall risk: critical|high|medium|low|clean

## Summary
| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Clean | 0 |

## Results
### <target> - <severity>
- Category:
- Evidence:
- Impact:
- Fix:

## Clean Items
- <items checked without findings>

## Coverage
- Files inspected
- MCP tools/checks run
- Checks skipped and why
```

If no issues are found, state that clearly and still include coverage and any skipped checks.
