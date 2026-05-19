# Trivy MCP Server — Design Spec
**Date:** 2026-05-19
**Status:** Approved for implementation

---

## Context

The `security-scan` skill currently invokes Trivy via Bash commands embedded in the skill `.md` file. In Claude Code Desktop App, the sandbox blocks direct Trivy execution. The fix is to wrap Trivy as an MCP server running outside the sandbox, while keeping the skill as the rules/analysis engine.

The target user installs skills by dragging `.md` files into Claude Code Desktop App's Customize menu. MCP server configuration requires a one-time setup step — but the user can ask Claude to run it, so there is no manual Terminal work required.

---

## Deliverables

| File | Purpose |
|------|---------|
| `server/trivy_server.py` | Python MCP server wrapping Trivy and OSV API |
| `setup.sh` | One-time setup: copies server, configures MCP in `~/.claude/settings.json` |
| `.mcp.json` | MCP server declaration (used when plugin is installed via Claude Code plugin system) |
| `skills/security-scan/security-scan.md` | Updated: replaces Bash Trivy calls with MCP tool calls |
| `README.md` | Updated: correct installation instructions |

---

## Installation Flow

### First-time install

```
User: "請幫我安裝 tomofound security scan"
  │
  ▼
Claude runs setup.sh via Bash tool:
  1. mkdir -p ~/.claude/plugins/data/tomofound/server/
  2. curl -fsSL <raw.githubusercontent.com/.../trivy_server.py>
       → ~/.claude/plugins/data/tomofound/server/trivy_server.py
  3. Patch ~/.claude/settings.json to add mcpServers entry
  4. Print: "請重啟 Claude Code，再將 security-scan.md 拖曳進 Customize > Skills"
  │
  ▼
User restarts Claude Code Desktop App
  │
  ▼
User drags security-scan.md into Customize > Skills
  │
  ▼
/security-scan is ready
```

### Updates

| What changed | Action |
|---|---|
| Skill rules (`.md`) | Drag new version into Customize > Skills (replace) |
| MCP server logic | Ask Claude to re-run `setup.sh` |

---

## MCP Server: `server/trivy_server.py`

### Bootstrap (first run, transparent to user)

The script bootstraps its own venv on first execution:

```
python3 trivy_server.py
  │
  ├─ venv exists at ~/.claude/plugins/data/tomofound/venv?
  │     NO  → python3 -m venv <venv>
  │           pip install mcp --quiet
  │
  └─ re-exec with venv Python if not already using it
```

This happens before the MCP server starts accepting connections. Takes ~5 seconds on first run, instant thereafter.

### Tools exposed

#### `scan_directory`

```
Input:  path (str), scanners (list[str], default: ["vuln", "secret"])
Output: { trivy_available: bool, results: <trivy JSON> | null, skipped_reason: str | null }
```

Behaviour:
1. Locate or install Trivy binary (same 3-level fallback: PATH → brew → GitHub Releases download to `~/.claude/tools/trivy`)
2. Detect best scan source for the given path (waterfall: lock file → manifest → node_modules → none)
3. Run `trivy fs <path> --scanners <scanners> --format json --quiet`
4. Return parsed JSON or `skipped_reason` if no scannable content found

#### `check_osv`

```
Input:  package (str), ecosystem (str)  e.g. "axios", "npm"
Output: { cve_count: int, vulns: [{ id, severity, summary }] }
```

Queries `https://api.osv.dev/v1/query` and returns structured results. Used for Level 4 fallback (source-only plugins with no manifest or lock file).

### Trivy auto-install logic (inside `scan_directory`)

```python
# 1. Already on PATH
# 2. brew install trivy
# 3. Download binary from GitHub Releases to ~/.claude/tools/trivy (no sudo)
# 4. None succeeded → return { trivy_available: false, skipped_reason: "trivy_unavailable" }
```

---

## `setup.sh`

```bash
#!/bin/bash
set -e

DEST=~/.claude/plugins/data/tomofound/server
BASE_URL=https://raw.githubusercontent.com/rotoyang/tomofound/main

mkdir -p "$DEST"

# Download MCP server script
curl -fsSL "$BASE_URL/server/trivy_server.py" -o "$DEST/trivy_server.py"
chmod +x "$DEST/trivy_server.py"

# Register MCP server in ~/.claude/settings.json
python3 - <<'PYEOF'
import json, os, sys
path = os.path.expanduser("~/.claude/settings.json")
with open(path) as f:
    s = json.load(f)
s.setdefault("mcpServers", {})["tomofound-trivy"] = {
    "command": "python3",
    "args": [os.path.expanduser("~/.claude/plugins/data/tomofound/server/trivy_server.py")]
}
with open(path, "w") as f:
    json.dump(s, f, indent=2)
print("✅ MCP server registered in ~/.claude/settings.json")
PYEOF

echo ""
echo "請重啟 Claude Code Desktop App，"
echo "再將 security-scan.md 拖曳進 Customize > Skills。"
```

---

## Updated `security-scan.md` Step 2

The Bash Trivy invocation block is replaced with MCP tool calls:

**Before (Bash, sandbox-blocked):**
```bash
$TRIVY_BIN fs <plugin-directory> --scanners vuln,secret --format json --quiet
```

**After (MCP tool call):**
```
Call MCP tool: scan_directory(path="<plugin-directory>", scanners=["vuln","secret"])
```

**Before (Bash OSV curl):**
```bash
curl -s "https://api.osv.dev/v1/query" -d '{"package": {...}}'
```

**After (MCP tool call):**
```
Call MCP tool: check_osv(package="<name>", ecosystem="<npm|PyPI|Go|crates.io>")
```

---

## `.mcp.json` (for future plugin-system installs)

```json
{
  "mcpServers": {
    "tomofound-trivy": {
      "command": "python3",
      "args": ["${CLAUDE_PLUGIN_ROOT}/server/trivy_server.py"]
    }
  }
}
```

---

## Updated README Installation Section

```markdown
## Installation

### Step 1 — Set up the MCP server (one time)

Ask Claude to install it:
> 「請幫我執行 https://github.com/rotoyang/tomofound 的安裝」

Claude will run setup.sh automatically. After it completes, **restart Claude Code Desktop App**.

### Step 2 — Add the skill

Download [security-scan.md](skills/security-scan/security-scan.md) and drag it into
**Customize > Skills** in Claude Code Desktop App.

### Updating

| What changed | Action |
|---|---|
| Scan rules | Replace security-scan.md in Customize > Skills |
| MCP server | Ask Claude to re-run setup.sh |
```

---

## Spec Self-Review

- No TBDs or placeholders
- Bootstrap flow handles both first-run (venv creation) and subsequent runs (instant)
- `setup.sh` is idempotent — safe to re-run for updates
- `.mcp.json` kept for future plugin-system compatibility
- Skill `.md` changes are minimal: only Step 2 Bash blocks replaced with MCP tool calls
- All other skill logic (LLM analysis, reporting, waterfall detection) unchanged

---

## Verification

1. Fresh machine with no Trivy: run `setup.sh` → should succeed, restart Claude Code, drag `.md`, run `/security-scan` → Trivy auto-installed by MCP server, scan completes
2. Re-run `setup.sh` → should be idempotent, no duplicate entries in `settings.json`
3. Remove `~/.claude/plugins/data/tomofound/venv` → next run should re-bootstrap silently
4. No network access: `scan_directory` returns `trivy_unavailable`, skill falls back to LLM-only mode
5. Plugin with only source code (no manifest): `scan_directory` returns `skipped`, `check_osv` called per imported package
