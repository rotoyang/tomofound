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
   - `extract_zip` for `.zip` pre-install scans (local path or `https://…zip` URL). Use `cleanup_clone` to remove its temp directory once done — both tools share the cleanup contract.
   - `scan_directory` for Trivy-backed CVE and secret checks.
   - `normalize_trivy` to convert raw `scan_directory.results` into the canonical finding shape (category/severity/file/line) consumed by `to_sarif` and the rest of the pipeline. Always call this when `results` is non-null.
   - `analyze_python` for AST + lightweight taint analysis of Python sources — pass a `.py` file or a directory; flags `eval`/`exec`/`pickle.loads`/`subprocess(shell=True)`/dynamic getattr and reports when env vars, `sys.argv`, `input()`, network responses, or MCP-handler arguments reach a code-execution or shell sink.
   - `read_file` for semantic review of code, prompts, skills, MCP configs, and config metadata.
   - `check_osv` only as a fallback when Trivy has no dependency version data.
   - `atr_update`, `atr_scan_path`, `atr_match`, `atr_status` for the Agent Threat Rules regex pre-filter (community-maintained YAML rule catalog for AI-agent threats; pinned v3.5.0, MIT). `atr_update` is user-initiated only — never auto-run. **Prefer `atr_scan_path` for multi-file targets** — it walks the directory, reads each file inside the MCP server, and runs the catalog against every body without streaming content back through the LLM (cheap and fast on the ~1000s of vendor docs bundled inside official plugins). Fall back to `atr_match` only for in-memory content (MCP exchange transcripts, assembled prompts) or when you've already loaded a file for LLM analysis. `atr_status` checks freshness.
   - `catalogs_status` to read the aggregated freshness state of every catalog the scanner consults (ATR, OSV, Trivy). Render this at the top of every scan report so the user can see which catalogs were used, what version, and what license.
   - `compute_risk_score` to deterministically derive the 0-100 score, recommendation, and badge from the merged canonical findings. Always use this for the report header — do not sum severity weights by hand or the score will drift between runs.
   - `to_sarif` to render the merged canonical findings as SARIF 2.1.0 for CI upload alongside the markdown report.
   - `write_file` when saving a report under `~/.tomofound/reports/` (write a markdown summary, a raw-findings JSON, and the SARIF document with a shared `YYYY-MM-DD-HH-MM` timestamp).
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
