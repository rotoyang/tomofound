#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""
import sys, os, subprocess, json, shutil, platform, urllib.request, tempfile

VENV = os.path.expanduser("~/.claude/plugins/data/tomofound/venv")
TOOLS_DIR = os.path.expanduser("~/.claude/tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")


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
