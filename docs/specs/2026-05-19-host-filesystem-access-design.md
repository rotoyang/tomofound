# Host Filesystem Access — Design Spec
**Date:** 2026-05-19
**Status:** Approved for implementation

---

## Problem

When `/security-scan` runs inside Claude Code Desktop App's sandbox, Bash commands and the `Read` tool cannot access `~/.claude`, `~/.gemini`, or `~/.openai` on the host filesystem because those paths are not mounted into the sandbox. The MCP server (`trivy_server.py`) runs as a separate process outside the sandbox and has full host filesystem access.

**Current broken flow:**
- Step 1: Bash `find ~/.claude/...` → 0 results (sandboxed)
- Step 3: Claude `Read` tool on those paths → may fail (sandboxed)
- Step 2: MCP `scan_directory` → works (outside sandbox) ✅

**Fix:** Move ALL host filesystem operations into the MCP server.

---

## Deliverables

| File | Change |
|------|--------|
| `server/trivy_server.py` | Add `discover_targets()` + `read_file()` helpers and MCP tool handlers |
| `tests/test_trivy_server.py` | Add tests for both new tools |
| `skills/security-scan/security-scan.md` | Step 1: replace Bash with `discover_targets` MCP call; Step 3: replace Read tool with `read_file` MCP call |

No changes to `scan_directory`, `check_osv`, `detect_scan_level`, `query_osv`, `setup.sh`, `.mcp.json`, or `README.md`.

---

## New MCP Tool: `discover_targets`

### Signature

```
Input:  target (str, optional): "claude" | "gemini" | "openai" | null
        path   (str, optional): absolute path for pre-install scan
Output: { "items": [ { "path": str, "tag": str, "plugin": str | null } ] }
```

Exactly one of `target` or `path` will be provided, or neither (meaning scan all).

### Scan roots

| `target` | Roots scanned |
|----------|--------------|
| `null` (default) | `~/.claude/plugins/cache`, `~/.claude/skills`, `~/.claude/settings.json`, `~/.claude/config.json`, `~/.gemini/settings.json`, `~/.gemini/oauth_creds.json`, `~/.openai/credentials.json` |
| `"claude"` | `~/.claude/plugins/cache`, `~/.claude/skills`, `~/.claude/settings.json`, `~/.claude/config.json` |
| `"gemini"` | `~/.gemini/settings.json`, `~/.gemini/oauth_creds.json` |
| `"openai"` | `~/.openai/credentials.json` |
| (custom `path`) | That path recursively |

### Skip directories

Always skip: `.git`, `node_modules`, `__pycache__`, `dist`, `build`, `out`, `.venv`, `venv`

These are compiled output or dependency caches — not source to audit.

### Tag assignment

| Tag | Files matched |
|-----|--------------|
| `LOCKFILE` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock` |
| `MANIFEST` | `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml` |
| `MCP` | `.mcp.json` |
| `SKILL` | `*.md` under `*/skills/*` or `~/.claude/skills/` |
| `CONFIG` | `settings.json`, `config.json`, `oauth_creds.json`, `credentials.json`, `*.env` |
| `CODE` | `*.ts`, `*.js`, `*.mjs`, `*.cjs`, `*.py`, `*.go`, `*.rs`, `*.sh`, `*.bash`, `*.zsh` |

### `plugin` field

For files under `~/.claude/plugins/cache/<source>/<name>/<version>/`, set `plugin` to `<name>`.
For files under `~/.claude/skills/`, set `plugin` to the filename stem.
For config files, set `plugin` to `null`.

### Return format

```json
{
  "items": [
    { "path": "/Users/you/.claude/plugins/cache/community/foo/0.1.0/server.ts", "tag": "CODE",    "plugin": "foo" },
    { "path": "/Users/you/.claude/plugins/cache/community/foo/0.1.0/.mcp.json",  "tag": "MCP",     "plugin": "foo" },
    { "path": "/Users/you/.claude/skills/bar.md",                                "tag": "SKILL",   "plugin": "bar" },
    { "path": "/Users/you/.claude/settings.json",                                "tag": "CONFIG",  "plugin": null  }
  ]
}
```

If no items are found, returns `{ "items": [] }`.

---

## New MCP Tool: `read_file`

### Signature

```
Input:  path (str): absolute path to read
Output: { "content": str, "size_bytes": int }
     or { "content": str, "size_bytes": int, "truncated": true }  — if file > 1MB
     or { "error": str }  — if file not found or unreadable
```

### Size limit

- Files ≤ 1 MB (1,048,576 bytes): return full content.
- Files > 1 MB: return first 1 MB of content with `"truncated": true`.
- Oversized files must be flagged in the scan report (see Report Changes below).

### Path restriction

Only paths under the following prefixes are allowed:
- `~/.claude/`
- `~/.gemini/`
- `~/.openai/`
- Any path passed as the `path` argument to `discover_targets` (custom scan root)

Attempts to read outside these roots return `{ "error": "path not permitted" }`.

---

## Updated `security-scan.md`

### Step 1 replacement

Replace the Bash `find` block with:

```
Call MCP tool: discover_targets
  target: <"claude" | "gemini" | "openai"> (if --target was specified)
  path:   <absolute path>                  (if a local path argument was given)
  (omit both for default full scan)
```

Use the returned `items` list as the scan target list. Tag each item exactly as returned.

For GitHub URL arguments: continue to use Bash `git clone` (that path is user-provided and accessible from the sandbox or can be done in the MCP server). After cloning, call `discover_targets` with `path` set to the cloned directory.

### Step 3 replacement

Replace all uses of Claude's `Read` tool with:

```
Call MCP tool: read_file
  path: "<absolute path from items list>"
```

Use the returned `content` field as the file content to send to Prompt A/B/C/D.

If `read_file` returns `{ "error": ... }`, skip that file and note "unreadable" in the report.

### Report changes

Add an `⚠️ Oversized Files` section at the end of the report when any file returned `truncated: true`:

```markdown
## ⚠️ Oversized Files (content truncated at 1 MB)

| File | Size |
|------|------|
| `~/.claude/plugins/cache/foo/dist/bundle.js` | 4.2 MB |

These files exceeded the 1 MB read limit. Only the first 1 MB was analyzed.
Adjust the limit in `trivy_server.py` if these files need full coverage.
```

---

## Spec Self-Review

- No TBDs or placeholders.
- `discover_targets` handles all three call modes: no args (full scan), `target` filter, custom `path`.
- `read_file` path restriction prevents reading arbitrary host files via MCP.
- Skip-dirs list (`dist`, `build`, `out`, etc.) prevents reading compiled artifacts.
- Oversized file logging satisfies the user's requirement for visibility into truncated scans.
- GitHub URL flow: `git clone` still runs in sandbox (writing to `~/.claude/tools/scan-tmp`), which is a sandbox-accessible path. No change needed there.
- Existing tools (`scan_directory`, `check_osv`) unchanged.
- All 13 existing tests must continue to pass.
