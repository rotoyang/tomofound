#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""

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


if __name__ == "__main__":
    _bootstrap()

import subprocess, json, shutil, platform, urllib.request, tempfile

TOOLS_DIR = os.path.expanduser("~/.claude/tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")

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
        os.path.expanduser("~/.claude/.mcp.json"),
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
            return f"{parts[0]}/{parts[1]}"  # publisher/plugin-name
        if len(parts) == 1:
            return parts[0]
    if path.startswith(skills_dir + os.sep):
        return os.path.splitext(os.path.basename(path))[0]
    return None


def _source_type(path: str, tag: str) -> str:
    cache = os.path.expanduser("~/.claude/plugins/cache")
    skills_dir = os.path.expanduser("~/.claude/skills")
    if path.startswith(cache + os.sep):
        return "plugin"
    if path.startswith(skills_dir + os.sep):
        return "skill"
    if tag == "MCP":
        return "mcp"
    if tag == "CONFIG":
        return "config"
    return "other"


def find_or_install_trivy() -> str | None:
    found = shutil.which("trivy")
    if found:
        return found

    if os.path.exists(TOOLS_TRIVY):
        return TOOLS_TRIVY

    try:
        with urllib.request.urlopen("https://api.github.com/repos/aquasecurity/trivy/releases/latest") as resp:
            data = json.loads(resp.read())
        version = data["tag_name"].lstrip("v")
        machine = subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip()
        arch = "ARM64" if machine == "arm64" else "64bit"
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-{arch}.tar.gz"
        os.makedirs(TOOLS_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = tmp.name
        urllib.request.urlretrieve(url, tmp_path)
        try:
            import tarfile
            with tarfile.open(tmp_path, "r:gz") as tf:
                member = tf.getmember("trivy")
                member.name = os.path.basename(member.name)
                tf.extract(member, TOOLS_DIR)
        finally:
            os.unlink(tmp_path)
        os.chmod(TOOLS_TRIVY, 0o755)
        return TOOLS_TRIVY
    except Exception:
        return None


def detect_scan_level(path: str) -> tuple[int, str]:
    lock_files = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
    manifest_files = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"}
    source_extensions = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".bash", ".zsh"}
    skip_dirs = {".git", "node_modules", "__pycache__"}

    for item in os.listdir(path):
        if item in lock_files:
            return (1, f"lock file ({item})")

    for item in os.listdir(path):
        if item in manifest_files:
            return (2, f"manifest ({item})")

    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        if os.path.isdir(item_path) and item == "node_modules":
            return (3, "node_modules directory")

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if os.path.splitext(file)[1] in source_extensions:
                return (4, "source code only")

    return (5, "no scannable content found")


def query_osv(package: str, ecosystem: str) -> dict:
    try:
        url = "https://api.osv.dev/v1/query"
        body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}})
        req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        vulns = data.get("vulns", [])
        result_vulns = []
        for vuln in vulns:
            result_vulns.append({
                "id": vuln.get("id", ""),
                "severity": vuln.get("database_specific", {}).get("severity", "unknown"),
                "summary": vuln.get("summary", "")
            })
        return {"cve_count": len(result_vulns), "vulns": result_vulns}
    except Exception as e:
        return {"cve_count": 0, "vulns": [], "error": str(e)}


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
                items.append({
                    "path": root,
                    "tag": tag,
                    "source_type": _source_type(root, tag),
                    "plugin": _plugin_from_path(root),
                })
        else:
            for dirpath, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for fname in files:
                    fpath = os.path.join(dirpath, fname)
                    tag = _tag_file(fpath)
                    if tag:
                        items.append({
                            "path": fpath,
                            "tag": tag,
                            "source_type": _source_type(fpath, tag),
                            "plugin": _plugin_from_path(fpath),
                        })

    return {"items": items}


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
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            size = os.fstat(f.fileno()).st_size
            if size <= FILE_READ_LIMIT:
                return {"content": f.read(), "size_bytes": size}
            return {"content": f.read(FILE_READ_LIMIT), "size_bytes": size, "truncated": True}
    except Exception as e:
        return {"error": str(e)}


try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    import asyncio
except ImportError:
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

        raise ValueError(f"Unknown tool: {name}")

    async def _main():
        async with stdio_server() as (read_stream, write_stream):
            await _server.run(
                read_stream, write_stream,
                _server.create_initialization_options()
            )

    if __name__ == "__main__":
        asyncio.run(_main())
