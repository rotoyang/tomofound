# Trivy MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap Trivy as a Python MCP server so the `security-scan` skill can call it from Claude Code Desktop App's sandbox, where direct Bash execution of Trivy is blocked.

**Architecture:** A self-bootstrapping Python script (`server/trivy_server.py`) creates its own venv and installs the `mcp` package on first run, then exposes two tools — `scan_directory` and `check_osv` — over stdio. A `setup.sh` script registers the server in `~/.claude/settings.json` and can be run by Claude on the user's behalf. The skill's Step 2 is updated to call MCP tools instead of raw Bash.

**Tech Stack:** Python 3 (pre-installed on macOS), `mcp` PyPI package, Trivy binary (auto-downloaded), OSV REST API.

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `server/trivy_server.py` | MCP server: bootstrap, `scan_directory`, `check_osv` |
| Create | `tests/test_trivy_server.py` | Unit tests for core functions |
| Create | `setup.sh` | One-time install: copy server, patch `settings.json` |
| Create | `.mcp.json` | MCP server declaration for plugin-system installs |
| Modify | `skills/security-scan/security-scan.md` | Replace Step 2 Bash blocks with MCP tool calls |
| Modify | `README.md` | Correct installation instructions |

---

## Task 1: Project scaffold and failing tests

**Files:**
- Create: `server/__init__.py` (empty)
- Create: `server/trivy_server.py` (stub)
- Create: `tests/__init__.py` (empty)
- Create: `tests/test_trivy_server.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p /Users/rotoyang/tomolab/tomofound/server
mkdir -p /Users/rotoyang/tomolab/tomofound/tests
touch /Users/rotoyang/tomolab/tomofound/server/__init__.py
touch /Users/rotoyang/tomolab/tomofound/tests/__init__.py
```

- [ ] **Step 2: Create stub `server/trivy_server.py`**

```python
#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""
import sys, os, subprocess, json, shutil, platform, urllib.request, tempfile

VENV = os.path.expanduser("~/.claude/plugins/data/tomofound/venv")
TOOLS_DIR = os.path.expanduser("~/.claude/tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")


def find_or_install_trivy() -> str | None:
    raise NotImplementedError


def detect_scan_level(path: str) -> tuple[int, str]:
    raise NotImplementedError


def query_osv(package: str, ecosystem: str) -> dict:
    raise NotImplementedError
```

- [ ] **Step 3: Write failing tests in `tests/test_trivy_server.py`**

```python
import os, sys, json, pytest
from unittest.mock import patch, MagicMock
import tempfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server.trivy_server import find_or_install_trivy, detect_scan_level, query_osv


# --- detect_scan_level ---

def test_detect_level1_lock_file():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "package-lock.json"), "w").close()
        level, desc = detect_scan_level(d)
        assert level == 1
        assert "lock file" in desc


def test_detect_level1_yarn_lock():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "yarn.lock"), "w").close()
        level, desc = detect_scan_level(d)
        assert level == 1


def test_detect_level2_manifest():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "package.json"), "w").close()
        level, desc = detect_scan_level(d)
        assert level == 2
        assert "manifest" in desc


def test_detect_level3_node_modules():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "node_modules"))
        level, desc = detect_scan_level(d)
        assert level == 3


def test_detect_level4_source_only():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "server.ts"), "w").close()
        level, desc = detect_scan_level(d)
        assert level == 4
        assert "source code" in desc


def test_detect_level5_empty():
    with tempfile.TemporaryDirectory() as d:
        level, desc = detect_scan_level(d)
        assert level == 5


def test_lock_file_takes_priority_over_manifest():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "package.json"), "w").close()
        open(os.path.join(d, "package-lock.json"), "w").close()
        level, _ = detect_scan_level(d)
        assert level == 1


# --- find_or_install_trivy ---

def test_find_trivy_on_path():
    with patch("shutil.which", return_value="/usr/local/bin/trivy"):
        result = find_or_install_trivy()
        assert result == "/usr/local/bin/trivy"


def test_find_trivy_in_tools_dir(tmp_path):
    fake_trivy = tmp_path / "trivy"
    fake_trivy.touch()
    with patch("server.trivy_server.TOOLS_TRIVY", str(fake_trivy)), \
         patch("shutil.which", return_value=None):
        result = find_or_install_trivy()
        assert result == str(fake_trivy)


def test_find_trivy_returns_none_on_all_failures():
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", return_value=MagicMock(returncode=1)), \
         patch("urllib.request.urlopen", side_effect=Exception("no network")), \
         patch("os.path.exists", return_value=False):
        result = find_or_install_trivy()
        assert result is None


# --- query_osv ---

def test_query_osv_returns_vulns():
    mock_response = json.dumps({"vulns": [
        {"id": "CVE-2022-0001", "summary": "Test vuln",
         "database_specific": {"severity": "HIGH"}}
    ]}).encode()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=MagicMock(read=lambda: mock_response))
    mock_ctx.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_ctx):
        result = query_osv("lodash", "npm")
        assert result["cve_count"] == 1
        assert result["vulns"][0]["id"] == "CVE-2022-0001"


def test_query_osv_empty_response():
    mock_response = json.dumps({"vulns": []}).encode()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=MagicMock(read=lambda: mock_response))
    mock_ctx.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_ctx):
        result = query_osv("safe-package", "npm")
        assert result["cve_count"] == 0
        assert result["vulns"] == []


def test_query_osv_network_error():
    with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        result = query_osv("axios", "npm")
        assert result["cve_count"] == 0
        assert "error" in result
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v 2>&1 | head -40
```

Expected: all tests fail with `NotImplementedError` or `ImportError`.

- [ ] **Step 5: Commit stub**

```bash
git -C /Users/rotoyang/tomolab/tomofound add server/ tests/
git -C /Users/rotoyang/tomolab/tomofound commit -m "test: add failing tests for trivy_server core functions"
```

---

## Task 2: Implement `detect_scan_level`

**Files:**
- Modify: `server/trivy_server.py`

- [ ] **Step 1: Implement `detect_scan_level`**

Replace the stub with:

```python
def detect_scan_level(path: str) -> tuple[int, str]:
    lock_files = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock",
    ]
    manifest_files = [
        "package.json", "requirements.txt", "pyproject.toml",
        "go.mod", "Cargo.toml",
    ]
    source_exts = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".bash", ".zsh"}

    for f in lock_files:
        if os.path.exists(os.path.join(path, f)):
            return (1, f"lock file ({f})")

    for f in manifest_files:
        if os.path.exists(os.path.join(path, f)):
            return (2, f"manifest ({f})")

    if os.path.exists(os.path.join(path, "node_modules")):
        return (3, "node_modules directory")

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
        for f in files:
            if any(f.endswith(ext) for ext in source_exts):
                return (4, "source code only")

    return (5, "no scannable content found")
```

- [ ] **Step 2: Run detect_scan_level tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "detect" -v
```

Expected: all 7 `detect_*` tests PASS.

- [ ] **Step 3: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add server/trivy_server.py
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: implement detect_scan_level"
```

---

## Task 3: Implement `find_or_install_trivy`

**Files:**
- Modify: `server/trivy_server.py`

- [ ] **Step 1: Implement `find_or_install_trivy`**

```python
def find_or_install_trivy() -> str | None:
    # 1. Already on PATH
    found = shutil.which("trivy")
    if found:
        return found

    # 2. Previously downloaded to tools dir
    if os.path.exists(TOOLS_TRIVY):
        return TOOLS_TRIVY

    # 3. Try Homebrew
    brew = shutil.which("brew")
    if brew:
        result = subprocess.run(
            [brew, "install", "trivy", "-q"],
            capture_output=True, timeout=120
        )
        if result.returncode == 0:
            found = shutil.which("trivy")
            if found:
                return found

    # 4. Download binary from GitHub Releases
    try:
        os.makedirs(TOOLS_DIR, exist_ok=True)
        with urllib.request.urlopen(
            "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
            timeout=15
        ) as r:
            tag = json.loads(r.read())["tag_name"]
        version = tag.lstrip("v")

        arch_map = {"x86_64": "64bit", "arm64": "ARM64"}
        arch = arch_map.get(platform.machine(), platform.machine())
        url = (
            f"https://github.com/aquasecurity/trivy/releases/download/{tag}/"
            f"trivy_{version}_macOS-{arch}.tar.gz"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar = os.path.join(tmp, "trivy.tar.gz")
            urllib.request.urlretrieve(url, tar)
            subprocess.run(
                ["tar", "xz", "-C", TOOLS_DIR, "-f", tar, "trivy"],
                check=True
            )
        os.chmod(TOOLS_TRIVY, 0o755)
        return TOOLS_TRIVY
    except Exception:
        return None
```

- [ ] **Step 2: Run find_or_install_trivy tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "trivy" -v
```

Expected: all 3 `*trivy*` tests PASS.

- [ ] **Step 3: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add server/trivy_server.py
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: implement find_or_install_trivy with 4-level fallback"
```

---

## Task 4: Implement `query_osv`

**Files:**
- Modify: `server/trivy_server.py`

- [ ] **Step 1: Implement `query_osv`**

```python
def query_osv(package: str, ecosystem: str) -> dict:
    payload = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}}
    ).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        vulns = data.get("vulns", [])
        return {
            "cve_count": len(vulns),
            "vulns": [
                {
                    "id": v.get("id"),
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                    "summary": v.get("summary", ""),
                }
                for v in vulns[:10]
            ],
        }
    except Exception as e:
        return {"cve_count": 0, "vulns": [], "error": str(e)}
```

- [ ] **Step 2: Run query_osv tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "osv" -v
```

Expected: all 3 `*osv*` tests PASS.

- [ ] **Step 3: Run all tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v
```

Expected: all 13 tests PASS.

- [ ] **Step 4: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add server/trivy_server.py
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: implement query_osv"
```

---

## Task 5: Wire up MCP server (bootstrap + tool handlers)

**Files:**
- Modify: `server/trivy_server.py` (add bootstrap block and MCP wiring at bottom)

- [ ] **Step 1: Add bootstrap block at top of file (before any imports that need mcp)**

Insert at the very top of `server/trivy_server.py`, before everything else except the module docstring:

```python
#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""

# Bootstrap: create venv and install mcp on first run, then re-exec.
import sys, os

VENV = os.path.expanduser("~/.claude/plugins/data/tomofound/venv")

def _bootstrap():
    venv_python = os.path.join(VENV, "bin", "python")
    if not os.path.exists(venv_python):
        import subprocess
        subprocess.run([sys.executable, "-m", "venv", VENV], check=True)
        subprocess.run([os.path.join(VENV, "bin", "pip"), "install", "mcp", "--quiet"], check=True)
    if not sys.executable.startswith(VENV):
        os.execv(venv_python, [venv_python] + sys.argv)

_bootstrap()

# --- rest of imports (now running under venv Python) ---
import subprocess, json, shutil, platform, urllib.request, tempfile
```

- [ ] **Step 2: Add MCP tool handlers at the bottom of `server/trivy_server.py`**

Append after the existing function definitions:

```python
# --- MCP server wiring ---
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    import asyncio
except ImportError:
    # Running tests outside venv — skip MCP wiring
    Server = None


if Server is not None:
    _server = Server("tomofound-trivy")

    @_server.list_tools()
    async def _list_tools():
        return [
            types.Tool(
                name="scan_directory",
                description="Scan a directory for CVEs and secrets using Trivy. Auto-installs Trivy if needed.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute path to scan"},
                        "scanners": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Scanners: vuln, secret (default: both)",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="check_osv",
                description="Check a package against the OSV vulnerability database.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string", "description": "Package name"},
                        "ecosystem": {
                            "type": "string",
                            "description": "Ecosystem: npm, PyPI, Go, crates.io",
                        },
                    },
                    "required": ["package", "ecosystem"],
                },
            ),
        ]

    @_server.call_tool()
    async def _call_tool(name: str, arguments: dict):
        if name == "scan_directory":
            path = arguments["path"]
            scanners = arguments.get("scanners", ["vuln", "secret"])
            trivy = find_or_install_trivy()
            level, level_desc = detect_scan_level(path)

            if not trivy:
                payload = {"trivy_available": False, "results": None,
                           "skipped_reason": "trivy_unavailable",
                           "scan_level": level, "scan_level_desc": level_desc}
                return [types.TextContent(type="text", text=json.dumps(payload))]

            if level == 5:
                payload = {"trivy_available": True, "results": None,
                           "skipped_reason": "no_dependency_info",
                           "scan_level": 5, "scan_level_desc": level_desc}
                return [types.TextContent(type="text", text=json.dumps(payload))]

            scan_path = path
            if level == 3:
                scan_path = os.path.join(path, "node_modules")
                scanners = ["vuln"]

            proc = subprocess.run(
                [trivy, "fs", scan_path,
                 "--scanners", ",".join(scanners),
                 "--format", "json", "--quiet"],
                capture_output=True, text=True, timeout=120,
            )
            try:
                results = json.loads(proc.stdout) if proc.stdout.strip() else {}
            except json.JSONDecodeError:
                results = {"raw": proc.stdout, "stderr": proc.stderr}

            payload = {"trivy_available": True, "results": results,
                       "skipped_reason": None,
                       "scan_level": level, "scan_level_desc": level_desc}
            return [types.TextContent(type="text", text=json.dumps(payload))]

        if name == "check_osv":
            result = query_osv(arguments["package"], arguments["ecosystem"])
            return [types.TextContent(type="text", text=json.dumps(result))]

        raise ValueError(f"Unknown tool: {name}")

    async def _main():
        async with stdio_server() as (read_stream, write_stream):
            await _server.run(
                read_stream, write_stream,
                _server.create_initialization_options()
            )

    if __name__ == "__main__":
        asyncio.run(_main())
```

- [ ] **Step 3: Run all tests (MCP wiring must not break unit tests)**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v
```

Expected: all 13 tests still PASS.

- [ ] **Step 4: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add server/trivy_server.py
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: add MCP server bootstrap and tool handlers"
```

---

## Task 6: Create `setup.sh`

**Files:**
- Create: `setup.sh`

- [ ] **Step 1: Create `setup.sh`**

```bash
cat > /Users/rotoyang/tomolab/tomofound/setup.sh << 'EOF'
#!/bin/bash
set -e

BASE_URL="https://raw.githubusercontent.com/rotoyang/tomofound/main"
DEST="$HOME/.claude/plugins/data/tomofound/server"

echo "Setting up tomofound security-scan MCP server..."

# 1. Copy server script
mkdir -p "$DEST"
curl -fsSL "$BASE_URL/server/trivy_server.py" -o "$DEST/trivy_server.py"
chmod +x "$DEST/trivy_server.py"
echo "✅ Server script installed to $DEST/trivy_server.py"

# 2. Register MCP server in ~/.claude/settings.json
python3 - <<PYEOF
import json, os

settings_path = os.path.expanduser("~/.claude/settings.json")
with open(settings_path) as f:
    settings = json.load(f)

server_entry = {
    "command": "python3",
    "args": [os.path.expanduser("~/.claude/plugins/data/tomofound/server/trivy_server.py")]
}

mcp = settings.setdefault("mcpServers", {})
if mcp.get("tomofound-trivy") == server_entry:
    print("ℹ️  MCP server already registered (no change)")
else:
    mcp["tomofound-trivy"] = server_entry
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("✅ MCP server registered in ~/.claude/settings.json")
PYEOF

echo ""
echo "─────────────────────────────────────────────"
echo "Installation complete. Next steps:"
echo ""
echo "  1. Restart Claude Code Desktop App"
echo "  2. Download security-scan.md from:"
echo "     https://github.com/rotoyang/tomofound/raw/main/skills/security-scan/security-scan.md"
echo "  3. Drag it into Customize > Skills"
echo "─────────────────────────────────────────────"
EOF
chmod +x /Users/rotoyang/tomolab/tomofound/setup.sh
```

- [ ] **Step 2: Verify setup.sh is valid bash (dry run)**

```bash
bash -n /Users/rotoyang/tomolab/tomofound/setup.sh && echo "Syntax OK"
```

Expected: `Syntax OK`

- [ ] **Step 3: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add setup.sh
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: add setup.sh for one-command MCP server installation"
```

---

## Task 7: Create `.mcp.json`

**Files:**
- Create: `.mcp.json`

- [ ] **Step 1: Create `.mcp.json`**

```bash
cat > /Users/rotoyang/tomolab/tomofound/.mcp.json << 'EOF'
{
  "mcpServers": {
    "tomofound-trivy": {
      "command": "python3",
      "args": ["${CLAUDE_PLUGIN_ROOT}/server/trivy_server.py"]
    }
  }
}
EOF
```

- [ ] **Step 2: Validate JSON**

```bash
python3 -m json.tool /Users/rotoyang/tomolab/tomofound/.mcp.json && echo "Valid JSON"
```

Expected: prints formatted JSON then `Valid JSON`.

- [ ] **Step 3: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add .mcp.json
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: add .mcp.json for plugin-system MCP server declaration"
```

---

## Task 8: Update `security-scan.md` Step 2

**Files:**
- Modify: `skills/security-scan/security-scan.md`

- [ ] **Step 1: Replace the entire Step 2 block**

Find the section starting with `### Step 2 — Set up Trivy (for CODE items only)` and replace it with:

```markdown
### Step 2 — CVE and secret scanning via MCP

For each plugin directory tagged `CODE`, call the MCP tool instead of running Bash directly:

**Scan a directory:**
```
Call MCP tool: scan_directory
  path: "<absolute path to plugin directory>"
  scanners: ["vuln", "secret"]
```

The tool returns JSON with:
- `trivy_available`: whether Trivy was found/installed
- `scan_level`: 1 (lock file) · 2 (manifest) · 3 (node_modules) · 4 (source only) · 5 (nothing)
- `scan_level_desc`: human-readable description of what was used
- `results`: Trivy JSON output, or `null` if skipped
- `skipped_reason`: `"trivy_unavailable"` | `"no_dependency_info"` | `null`

If `skipped_reason` is `"no_dependency_info"` (Level 5 — source code only), proceed to Level 4 fallback:
read all source files, extract every import/require/from/use statement, collect unique
third-party package names, then for each package:

```
Call MCP tool: check_osv
  package: "<package name>"
  ecosystem: "<npm|PyPI|Go|crates.io>"
```

The tool returns `{ cve_count, vulns: [{ id, severity, summary }] }`.
Report any package with `cve_count > 0` as `[SUPPLY_CHAIN]` severity `medium`:
"Version unknown — package has N known CVEs across all versions."

If `skipped_reason` is `"trivy_unavailable"`, note "Trivy unavailable — CVE scan skipped" in the
report header and continue with LLM-only analysis.
```

- [ ] **Step 2: Verify the skill file has no remaining raw Bash Trivy invocations**

```bash
grep -n "TRIVY_BIN\|brew install trivy\|curl.*trivy" \
  /Users/rotoyang/tomolab/tomofound/skills/security-scan/security-scan.md
```

Expected: no output (all Trivy Bash removed).

- [ ] **Step 3: Commit**

```bash
git -C /Users/rotoyang/tomolab/tomofound add skills/security-scan/security-scan.md
git -C /Users/rotoyang/tomolab/tomofound commit -m "feat: replace Bash Trivy calls with MCP tool calls in security-scan skill"
```

---

## Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the Installation section with correct instructions**

Replace the entire `## Installation` section with:

```markdown
## Installation

### Step 1 — Set up the MCP server (one time only)

Ask Claude to install it for you:

> 「請幫我執行 https://github.com/rotoyang/tomofound 的安裝」

Claude will download and run `setup.sh` using its Bash tool. When it finishes,
**restart Claude Code Desktop App**.

Or run it yourself in Terminal:
```bash
curl -fsSL https://raw.githubusercontent.com/rotoyang/tomofound/main/setup.sh | bash
```

### Step 2 — Add the skill

1. Download [security-scan.md](skills/security-scan/security-scan.md)
2. Open Claude Code Desktop App → **Customize > Skills**
3. Drag `security-scan.md` into the Skills area

`/security-scan` is now available.

### Updating

| What changed | Action |
|---|---|
| Scan rules (`.md`) | Download new `security-scan.md`, drag into Customize > Skills (Replace) |
| MCP server (`trivy_server.py`) | Ask Claude to re-run `setup.sh` |
```

- [ ] **Step 2: Commit and push everything**

```bash
git -C /Users/rotoyang/tomolab/tomofound add README.md
git -C /Users/rotoyang/tomolab/tomofound commit -m "docs: update README with correct installation instructions"
git -C /Users/rotoyang/tomolab/tomofound push
```

---

## Verification Checklist

- [ ] `python3 -m pytest tests/ -v` — all 13 tests pass
- [ ] `bash -n setup.sh` — no syntax errors
- [ ] `python3 -m json.tool .mcp.json` — valid JSON
- [ ] `grep -n "TRIVY_BIN" skills/security-scan/security-scan.md` — no output
- [ ] Run `setup.sh` → check `~/.claude/settings.json` has `tomofound-trivy` entry
- [ ] Run `setup.sh` again → no duplicate entry (idempotent)
- [ ] Restart Claude Code Desktop App → run `/security-scan` → no sandbox errors
