# Host Filesystem Access via MCP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `discover_targets` and `read_file` MCP tools so the security-scan skill can discover and read files on the host filesystem from within Claude Code Desktop App's sandbox.

**Architecture:** Both new tools are Python helper functions in `server/trivy_server.py`, exposed as MCP tools alongside the existing `scan_directory` and `check_osv`. The skill's Step 1 calls `discover_targets` instead of Bash `find`, and Step 3 calls `read_file` instead of Claude's `Read` tool. All existing functions and their 13 tests are untouched.

**Tech Stack:** Python 3, `mcp` PyPI package (already in venv), `pytest` + `unittest.mock`.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Modify | `server/trivy_server.py` | Add constants + `_tag_file`, `_plugin_from_path`, `discover_targets`, `read_file` helpers; extend `_list_tools` + `_call_tool` MCP handlers |
| Modify | `tests/test_trivy_server.py` | Add 10 new tests (6 for `discover_targets`, 4 for `read_file`) |
| Modify | `skills/security-scan/security-scan.md` | Step 1: replace Bash `find` block; Step 3: replace `Read` tool; Step 4: add oversized files report section |

---

## Task 1: Failing tests for `discover_targets`

**Files:**
- Modify: `tests/test_trivy_server.py`

- [ ] **Step 1: Add the import and 6 failing tests**

Open `tests/test_trivy_server.py`. Change the import on line 6 from:
```python
from server.trivy_server import find_or_install_trivy, detect_scan_level, query_osv
```
to:
```python
from server.trivy_server import find_or_install_trivy, detect_scan_level, query_osv, discover_targets, read_file
```

Then append at the end of the file:

```python
# --- discover_targets ---

def test_discover_targets_finds_code_file():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "server.ts"), "w").close()
        result = discover_targets(path=d)
        paths = [i["path"] for i in result["items"]]
        assert any("server.ts" in p for p in paths)
        tags = [i["tag"] for i in result["items"] if "server.ts" in i["path"]]
        assert tags == ["CODE"]


def test_discover_targets_finds_skill_file():
    with tempfile.TemporaryDirectory() as d:
        skills_dir = os.path.join(d, "skills")
        os.makedirs(skills_dir)
        open(os.path.join(skills_dir, "my-skill.md"), "w").close()
        result = discover_targets(path=d)
        tags = [i["tag"] for i in result["items"] if "my-skill.md" in i["path"]]
        assert tags == ["SKILL"]


def test_discover_targets_finds_lockfile():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "package-lock.json"), "w").close()
        result = discover_targets(path=d)
        tags = [i["tag"] for i in result["items"] if "package-lock.json" in i["path"]]
        assert tags == ["LOCKFILE"]


def test_discover_targets_finds_mcp_json():
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, ".mcp.json"), "w").close()
        result = discover_targets(path=d)
        tags = [i["tag"] for i in result["items"] if ".mcp.json" in i["path"]]
        assert tags == ["MCP"]


def test_discover_targets_skips_dist_dir():
    with tempfile.TemporaryDirectory() as d:
        dist_dir = os.path.join(d, "dist")
        os.makedirs(dist_dir)
        open(os.path.join(dist_dir, "bundle.js"), "w").close()
        result = discover_targets(path=d)
        paths = [i["path"] for i in result["items"]]
        assert not any("bundle.js" in p for p in paths)


def test_discover_targets_empty_dir_returns_empty():
    with tempfile.TemporaryDirectory() as d:
        result = discover_targets(path=d)
        assert result["items"] == []
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "discover" -v 2>&1 | tail -15
```

Expected: 6 errors with `ImportError: cannot import name 'discover_targets'`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_trivy_server.py
git commit -m "test: add failing tests for discover_targets"
```

---

## Task 2: Implement `discover_targets`

**Files:**
- Modify: `server/trivy_server.py`

- [ ] **Step 1: Add constants after the existing `TOOLS_TRIVY` line**

In `server/trivy_server.py`, find the line:
```python
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")
```

Insert immediately after it:

```python
FILE_READ_LIMIT = 1024 * 1024  # 1 MB

_LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
_MANIFEST_NAMES = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"}
_CONFIG_NAMES = {"settings.json", "config.json", "oauth_creds.json", "credentials.json"}
_CODE_EXTS = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".bash", ".zsh"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", "out", ".venv", "venv"}

_STANDARD_ROOTS = {
    "claude": [
        os.path.expanduser("~/.claude/plugins/cache"),
        os.path.expanduser("~/.claude/skills"),
        os.path.expanduser("~/.claude/settings.json"),
        os.path.expanduser("~/.claude/config.json"),
    ],
    "gemini": [
        os.path.expanduser("~/.gemini/settings.json"),
        os.path.expanduser("~/.gemini/oauth_creds.json"),
    ],
    "openai": [
        os.path.expanduser("~/.openai/credentials.json"),
    ],
}

_READ_ALLOWED_PREFIXES = [
    os.path.expanduser("~/.claude/"),
    os.path.expanduser("~/.gemini/"),
    os.path.expanduser("~/.openai/"),
]
```

- [ ] **Step 2: Add `_tag_file` and `_plugin_from_path` helpers before `find_or_install_trivy`**

Insert before the `def find_or_install_trivy():` line:

```python
def _tag_file(path: str) -> str | None:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    skills_marker = os.sep + "skills" + os.sep
    if name in _LOCKFILE_NAMES:
        return "LOCKFILE"
    if name in _MANIFEST_NAMES:
        return "MANIFEST"
    if name == ".mcp.json":
        return "MCP"
    if name.endswith(".md") and (skills_marker in path or path.startswith(os.path.expanduser("~/.claude/skills/"))):
        return "SKILL"
    if name in _CONFIG_NAMES or name.endswith(".env"):
        return "CONFIG"
    if ext in _CODE_EXTS:
        return "CODE"
    return None


def _plugin_from_path(path: str) -> str | None:
    cache = os.path.expanduser("~/.claude/plugins/cache")
    skills_dir = os.path.expanduser("~/.claude/skills")
    if path.startswith(cache + os.sep):
        parts = path[len(cache) + 1:].split(os.sep)
        if len(parts) >= 2:
            return parts[1]
    if path.startswith(skills_dir + os.sep):
        return os.path.splitext(os.path.basename(path))[0]
    return None
```

- [ ] **Step 3: Add `discover_targets` after `query_osv`**

Insert after the closing of `def query_osv(...)`:

```python
def discover_targets(target: str = None, path: str = None) -> dict:
    if path:
        roots = [path]
    elif target:
        roots = _STANDARD_ROOTS.get(target, [])
    else:
        roots = [r for v in _STANDARD_ROOTS.values() for r in v]

    items = []
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.exists(root):
            continue
        if os.path.isfile(root):
            tag = _tag_file(root)
            if tag:
                items.append({"path": root, "tag": tag, "plugin": _plugin_from_path(root)})
        else:
            for dirpath, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for fname in files:
                    fpath = os.path.join(dirpath, fname)
                    tag = _tag_file(fpath)
                    if tag:
                        items.append({"path": fpath, "tag": tag, "plugin": _plugin_from_path(fpath)})

    return {"items": items}
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "discover" -v 2>&1 | tail -15
```

Expected: all 6 `discover_*` tests PASS. The existing 13 tests must still pass too:

```bash
python3 -m pytest tests/test_trivy_server.py -v 2>&1 | tail -5
```

Expected: `19 passed`.

- [ ] **Step 5: Commit**

```bash
git add server/trivy_server.py
git commit -m "feat: implement discover_targets with tag and plugin resolution"
```

---

## Task 3: Failing tests for `read_file`

**Files:**
- Modify: `tests/test_trivy_server.py`

- [ ] **Step 1: Append 4 failing tests**

Add to the end of `tests/test_trivy_server.py`:

```python
# --- read_file ---

def test_read_file_returns_content(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    result = read_file(str(f), root=str(tmp_path))
    assert result["content"] == "hello world"
    assert result["size_bytes"] == len("hello world")
    assert "truncated" not in result


def test_read_file_truncates_large_file(tmp_path):
    f = tmp_path / "big.txt"
    # Write 1MB + 1 byte
    content = "x" * (1024 * 1024 + 1)
    f.write_text(content)
    result = read_file(str(f), root=str(tmp_path))
    assert result["truncated"] is True
    assert result["size_bytes"] == len(content)
    assert len(result["content"]) == 1024 * 1024


def test_read_file_rejects_unpermitted_path(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("sensitive")
    # No root= provided, path not under ~/.claude/~/.gemini/~/.openai/
    result = read_file(str(f))
    assert "error" in result
    assert "not permitted" in result["error"]


def test_read_file_returns_error_for_missing_file(tmp_path):
    result = read_file(str(tmp_path / "nonexistent.txt"), root=str(tmp_path))
    assert "error" in result
    assert "not found" in result["error"]
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -k "read_file" -v 2>&1 | tail -10
```

Expected: 4 errors with `ImportError: cannot import name 'read_file'`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_trivy_server.py
git commit -m "test: add failing tests for read_file"
```

---

## Task 4: Implement `read_file`

**Files:**
- Modify: `server/trivy_server.py`

- [ ] **Step 1: Add `read_file` after `discover_targets`**

Insert immediately after the closing of `def discover_targets(...)`:

```python
def read_file(path: str, root: str = None) -> dict:
    abs_path = os.path.abspath(os.path.expanduser(path))
    allowed = list(_READ_ALLOWED_PREFIXES)
    if root:
        allowed.append(os.path.abspath(os.path.expanduser(root)))
    if not any(abs_path.startswith(p) for p in allowed):
        return {"error": "path not permitted"}
    if not os.path.isfile(abs_path):
        return {"error": "file not found"}
    try:
        size = os.path.getsize(abs_path)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            if size <= FILE_READ_LIMIT:
                return {"content": f.read(), "size_bytes": size}
            return {"content": f.read(FILE_READ_LIMIT), "size_bytes": size, "truncated": True}
    except Exception as e:
        return {"error": str(e)}
```

- [ ] **Step 2: Run all tests**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v 2>&1 | tail -8
```

Expected: `23 passed` (13 original + 6 discover + 4 read_file).

- [ ] **Step 3: Commit**

```bash
git add server/trivy_server.py
git commit -m "feat: implement read_file with 1MB limit and path restriction"
```

---

## Task 5: Wire `discover_targets` + `read_file` as MCP tools

**Files:**
- Modify: `server/trivy_server.py` (the `_list_tools` and `_call_tool` async functions inside `if Server is not None:`)

- [ ] **Step 1: Extend `_list_tools` to include two new tools**

In the `_list_tools` function, the current `return [...]` has two tools (`scan_directory` and `check_osv`). Add two more entries to the list, so the full return is:

```python
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
            types.Tool(
                name="discover_targets",
                description="Discover all scannable AI tool extension files on the host filesystem (outside sandbox).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "enum": ["claude", "gemini", "openai"],
                            "description": "Limit scan to one AI tool directory",
                        },
                        "path": {
                            "type": "string",
                            "description": "Scan a specific absolute path instead of installed tools",
                        },
                    },
                },
            ),
            types.Tool(
                name="read_file",
                description="Read a file from the host filesystem (up to 1 MB). Returns content as text.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute path to the file"},
                        "root": {
                            "type": "string",
                            "description": "Custom scan root — required for paths outside ~/.claude, ~/.gemini, ~/.openai",
                        },
                    },
                    "required": ["path"],
                },
            ),
        ]
```

- [ ] **Step 2: Extend `_call_tool` with two new `if` blocks**

In the `_call_tool` function, add after the `if name == "check_osv":` block and before `raise ValueError(...)`:

```python
        if name == "discover_targets":
            result = discover_targets(
                target=arguments.get("target"),
                path=arguments.get("path"),
            )
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "read_file":
            result = read_file(
                path=arguments["path"],
                root=arguments.get("root"),
            )
            return [types.TextContent(type="text", text=json.dumps(result))]
```

- [ ] **Step 3: Run all tests to confirm nothing broke**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v 2>&1 | tail -5
```

Expected: `23 passed`.

- [ ] **Step 4: Commit**

```bash
git add server/trivy_server.py
git commit -m "feat: expose discover_targets and read_file as MCP tools"
```

---

## Task 6: Update `security-scan.md`

**Files:**
- Modify: `skills/security-scan/security-scan.md`

Three changes in one commit.

- [ ] **Step 1: Replace the Step 1 Bash discovery block**

Find this exact block (lines 39–72):

```
Otherwise (default scan), run:
```bash
# Discover installed plugins and connectors (all languages, skip node_modules)
find ~/.claude/plugins/cache -type f \( \
  -name "*.ts" -o -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \
  -o -name "*.py" -o -name "*.go" -o -name "*.rs" \
  -o -name "*.sh" -o -name "*.bash" -o -name "*.zsh" \
  -o -name "package.json" -o -name "requirements.txt" \
  -o -name "pyproject.toml" -o -name "go.mod" -o -name "Cargo.toml" \
  -o -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \
  -o -name "poetry.lock" -o -name "Pipfile.lock" -o -name "go.sum" -o -name "Cargo.lock" \
  -o -name "*.env" \
\) ! -path "*/.git/*" 2>/dev/null

# Discover MCP configuration files (separate category)
find ~/.claude/plugins/cache -name ".mcp.json" 2>/dev/null
find ~/.claude -maxdepth 2 -name ".mcp.json" 2>/dev/null

# Discover installed skills
find ~/.claude/plugins/cache -name "*.md" -path "*/skills/*" 2>/dev/null
find ~/.claude/skills -name "*.md" 2>/dev/null 2>/dev/null

# Discover config files
ls -la \
  ~/.claude/settings.json \
  ~/.claude/config.json \
  ~/.gemini/settings.json \
  ~/.gemini/oauth_creds.json \
  ~/.openai/credentials.json 2>/dev/null
```

Tag each discovered item as one of: `CODE` (source files), `MANIFEST` (package.json, requirements.txt, go.mod, Cargo.toml), `LOCKFILE` (package-lock.json, yarn.lock, go.sum, Cargo.lock, etc.), `MCP` (.mcp.json), `SKILL` (.md), or `CONFIG` (credential/settings files).

Apply `--target` filter if specified: only include items under the matching root path.
```

Replace it with:

```
Otherwise, for a default scan or `--target` scan, call the MCP tool:

```
Call MCP tool: discover_targets
  target: <"claude" | "gemini" | "openai">  ← omit if no --target was specified
```

For a local path argument, call:

```
Call MCP tool: discover_targets
  path: "<absolute local path>"
```

The tool returns `{ "items": [ { "path", "tag", "plugin" } ] }`.
`tag` is one of: `CODE`, `MANIFEST`, `LOCKFILE`, `MCP`, `SKILL`, `CONFIG`.
`plugin` is the plugin name (or `null` for config files).
Use this items list as the scan target list for all subsequent steps.
```

- [ ] **Step 2: Replace the Step 3 Read-tool instruction**

Find this line:
```
For each item, read the file content with the Read tool, then analyze using the appropriate prompt below.
```

Replace with:
```
For each item, read the file content by calling the MCP tool:

```
Call MCP tool: read_file
  path: "<item path from discover_targets>"
  root: "<custom scan root>"  ← only needed for pre-install scans outside ~/.claude/~/.gemini/~/.openai
```

If `read_file` returns `{ "error": ... }`, skip the file and note "unreadable" in that item's report entry.
If `read_file` returns `{ "truncated": true, ... }`, add the file to the oversized files list (see Step 4).
Use the returned `content` field as the file content to send to the appropriate Prompt below.
```

- [ ] **Step 3: Add the oversized files section to Step 4**

Find this block in Step 4:

```
5. If this was a pre-installation scan (temp dir), clean up:
```bash
rm -rf ~/.claude/tools/scan-tmp
```
```

Insert before it:

```
5. If any `read_file` calls returned `truncated: true`, append this section to the report:

```markdown
## ⚠️ Oversized Files (content truncated at 1 MB)

| File | Size |
|------|------|
| `<path>` | <size_bytes / 1048576 rounded to 1 decimal> MB |

These files exceeded the 1 MB read limit — only the first 1 MB was analyzed.
If full coverage is needed, increase `FILE_READ_LIMIT` in `trivy_server.py`.
```

6. If this was a pre-installation scan (temp dir), clean up:
```bash
rm -rf ~/.claude/tools/scan-tmp
```
```

(Note: the old step 5 becomes step 6, and old step 6 becomes step 7 — renumber accordingly.)

- [ ] **Step 4: Verify no Bash find or Read tool references remain for host paths**

```bash
grep -n "find ~/\.\(claude\|gemini\|openai\)\|Read tool\|ls -la" \
  /Users/rotoyang/tomolab/tomofound/skills/security-scan/security-scan.md
```

Expected: no output.

- [ ] **Step 5: Run all tests one final time**

```bash
cd /Users/rotoyang/tomolab/tomofound && python3 -m pytest tests/test_trivy_server.py -v 2>&1 | tail -5
```

Expected: `23 passed`.

- [ ] **Step 6: Commit and push**

```bash
git add skills/security-scan/security-scan.md
git commit -m "feat: replace sandbox Bash/Read with MCP discover_targets and read_file"
git push
```

---

## Verification Checklist

- [ ] `python3 -m pytest tests/ -v` — 23 tests pass (13 original + 6 discover + 4 read_file)
- [ ] `grep -n "find ~/\." skills/security-scan/security-scan.md` — no output
- [ ] `grep -n "Read tool" skills/security-scan/security-scan.md` — no output
- [ ] Run `setup.sh` to push updated `trivy_server.py` to `~/.claude/plugins/data/tomofound/server/`
- [ ] Restart Claude Code Desktop App → run `/security-scan` → confirms scan targets found
