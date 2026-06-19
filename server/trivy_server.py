#!/usr/bin/env python3
"""Trivy MCP server for tomofound — security scanner for AI tool extensions."""

import sys, os

VENV = os.path.expanduser("~/.tomofound/venv")

# Pinned dependencies — when bumping any entry, also update the Supply chain
# table in README.md (see CLAUDE.md). Use lower bounds so security patches
# from upstream can ship; pin upper bounds at the next major to block
# breaking changes.
_PIP_DEPS = [
    "mcp==1.28.0",
    "PyYAML>=6.0,<7",
]
_MCP_PIN = _PIP_DEPS[0]  # back-compat name for any external reader of the constant

# Bump this string when _PIP_DEPS changes so existing venvs auto-reinstall the
# new set on next server start. The bootstrap writes the current value to
# ~/.tomofound/venv/.tomofound-deps; mismatch triggers a pip install --upgrade.
_DEPS_VERSION = "2"


def _bootstrap():
    venv_python = os.path.join(VENV, "bin", "python")
    marker = os.path.join(VENV, ".tomofound-deps")
    deps_current = None
    if os.path.isfile(marker):
        try:
            with open(marker) as f:
                deps_current = f.read().strip()
        except OSError:
            deps_current = None

    if not os.path.exists(venv_python) or deps_current != _DEPS_VERSION:
        import subprocess
        if not os.path.exists(venv_python):
            subprocess.run([sys.executable, "-m", "venv", VENV], check=True)
        subprocess.run(
            [os.path.join(VENV, "bin", "pip"), "install", *_PIP_DEPS,
             "--upgrade", "--quiet"],
            check=True,
        )
        try:
            with open(marker, "w") as f:
                f.write(_DEPS_VERSION)
        except OSError:
            pass  # marker is an optimisation, not a correctness gate

    if not sys.executable.startswith(VENV):
        os.execv(venv_python, [venv_python] + sys.argv)


if __name__ == "__main__":
    _bootstrap()

import subprocess, json, shutil, platform, urllib.request, urllib.error, tempfile, re, zipfile, ipaddress, socket
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from python_analyzer import analyze_python  # noqa: E402
import atr_catalog  # noqa: E402

DATA_ROOT = os.path.expanduser("~/.tomofound")
TOOLS_DIR = os.path.join(DATA_ROOT, "tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")
CLONE_PREFIX = "tomofound-scan-"
REPORTS_DIR = os.path.join(DATA_ROOT, "reports")

_PROMPT_NAME = "security_scan"
_PROMPT_SOURCE_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "security-scan", "security-scan.md"),
    os.path.join(DATA_ROOT, "skills", "security-scan", "security-scan.md"),
]

FILE_READ_LIMIT = 1024 * 1024  # 1 MB
FILE_WRITE_LIMIT = 8 * 1024 * 1024  # 8 MB
ZIP_DOWNLOAD_LIMIT = 50 * 1024 * 1024  # 50 MB compressed
ZIP_UNCOMPRESSED_LIMIT = 200 * 1024 * 1024  # 200 MB total uncompressed
ZIP_MEMBER_LIMIT = 10000  # max entries in an archive

_LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
_MANIFEST_NAMES = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"}
_CONFIG_NAMES = {"settings.json", "config.json", "oauth_creds.json", "credentials.json", "auth.json", "config.toml"}
_CODE_EXTS = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".bash", ".zsh"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", "out", ".venv", "venv"}
_SKILL_DIR_MARKERS = tuple(os.sep + d + os.sep for d in ("skills", "agents", "commands", "prompts"))

_STANDARD_ROOTS = {
    "claude": [
        os.path.expanduser("~/.claude/plugins/cache"),
        os.path.expanduser("~/.claude/plugins/repos"),
        os.path.expanduser("~/.claude/skills"),
        os.path.expanduser("~/.claude/agents"),
        os.path.expanduser("~/.claude/commands"),
        os.path.expanduser("~/.claude/.mcp.json"),
        os.path.expanduser("~/.claude/settings.json"),
        os.path.expanduser("~/.claude/config.json"),
    ],
    "gemini": [
        os.path.expanduser("~/.gemini/extensions"),
        os.path.expanduser("~/.gemini/config/plugins"),
        os.path.expanduser("~/.gemini/commands"),
        os.path.expanduser("~/.gemini/settings.json"),
        os.path.expanduser("~/.gemini/oauth_creds.json"),
        os.path.expanduser("~/.gemini/.env"),
    ],
    "openai": [
        os.path.expanduser("~/.codex/auth.json"),
        os.path.expanduser("~/.codex/config.toml"),
        os.path.expanduser("~/.codex/AGENTS.md"),
        os.path.expanduser("~/.codex/skills"),
        os.path.expanduser("~/.codex/plugins/cache"),
        os.path.expanduser("~/.codex/prompts"),
    ],
}

_READ_ALLOWED_PREFIXES = [
    os.path.expanduser("~/.claude/"),
    os.path.expanduser("~/.gemini/"),
    os.path.expanduser("~/.codex/"),
]

_WRITE_ALLOWED_PREFIXES = [
    DATA_ROOT + os.sep,
]

_SENSITIVE_HOME_SUBDIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh")

_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")


def _ensure_trailing_sep(p: str) -> str:
    return p if p.endswith(os.sep) else p + os.sep


def _is_safe_root(root: str) -> bool:
    """Permit custom scan roots only under HOME or a system temp dir,
    and reject sensitive HOME subdirs (~/.ssh, ~/.aws, ...).
    Uses realpath to defend against symlink-escape."""
    real_root = os.path.realpath(os.path.expanduser(root))
    home = os.path.realpath(os.path.expanduser("~"))
    tmp_candidates = (tempfile.gettempdir(), "/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp")
    bases = {home}
    for t in tmp_candidates:
        if os.path.isdir(t):
            bases.add(os.path.realpath(t))
    if not any(real_root == b or real_root.startswith(b + os.sep) for b in bases):
        return False
    for sub in _SENSITIVE_HOME_SUBDIRS:
        blocked = os.path.join(home, sub)
        if real_root == blocked or real_root.startswith(blocked + os.sep):
            return False
    return True


def _tag_file(path: str) -> str | None:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    in_skill_dir = any(m in path for m in _SKILL_DIR_MARKERS) or path.startswith(os.path.expanduser("~/.claude/skills/"))
    if name in _LOCKFILE_NAMES:
        return "LOCKFILE"
    if name in _MANIFEST_NAMES:
        return "MANIFEST"
    if name == ".mcp.json":
        return "MCP"
    if name == "AGENTS.md":
        return "SKILL"
    if name.endswith(".md") and in_skill_dir:
        return "SKILL"
    if ext == ".toml" and (os.sep + "commands" + os.sep) in path:
        return "SKILL"
    if name in _CONFIG_NAMES or name.endswith(".env"):
        return "CONFIG"
    if ext in _CODE_EXTS:
        return "CODE"
    return None


def _plugin_from_path(path: str) -> str | None:
    nested_roots = (
        os.path.expanduser("~/.claude/plugins/cache"),
        os.path.expanduser("~/.claude/plugins/repos"),
        os.path.expanduser("~/.codex/plugins/cache"),
    )
    for base in nested_roots:
        if path.startswith(base + os.sep):
            parts = path[len(base) + 1:].split(os.sep)
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"  # publisher/plugin-name
            if len(parts) == 1:
                return parts[0]

    gemini_ext = os.path.expanduser("~/.gemini/extensions")
    if path.startswith(gemini_ext + os.sep):
        return path[len(gemini_ext) + 1:].split(os.sep)[0]

    gemini_config_plugins = os.path.expanduser("~/.gemini/config/plugins")
    if path.startswith(gemini_config_plugins + os.sep):
        return path[len(gemini_config_plugins) + 1:].split(os.sep)[0]

    leaf_roots = (
        os.path.expanduser("~/.claude/skills"),
        os.path.expanduser("~/.claude/agents"),
        os.path.expanduser("~/.claude/commands"),
        os.path.expanduser("~/.gemini/commands"),
        os.path.expanduser("~/.codex/skills"),
        os.path.expanduser("~/.codex/prompts"),
    )
    for base in leaf_roots:
        if path.startswith(base + os.sep):
            return os.path.splitext(os.path.basename(path))[0]
    return None


def _source_type(path: str, tag: str) -> str:
    plugin_roots = (
        os.path.expanduser("~/.claude/plugins/cache"),
        os.path.expanduser("~/.claude/plugins/repos"),
        os.path.expanduser("~/.gemini/extensions"),
        os.path.expanduser("~/.gemini/config/plugins"),
        os.path.expanduser("~/.codex/plugins/cache"),
    )
    if any(path.startswith(r + os.sep) for r in plugin_roots):
        return "plugin"
    if tag == "SKILL":
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
        system = platform.system()
        machine = platform.machine().lower()
        if system == "Darwin":
            os_name = "macOS"
        elif system == "Linux":
            os_name = "Linux"
        else:
            return None
        if machine in ("arm64", "aarch64"):
            arch = "ARM64"
        elif machine in ("x86_64", "amd64"):
            arch = "64bit"
        else:
            return None
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os_name}-{arch}.tar.gz"
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
        if not _is_safe_root(path):
            return {"error": "path not permitted", "items": []}
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
    allowed = [_ensure_trailing_sep(p) for p in _READ_ALLOWED_PREFIXES]
    if root:
        if not _is_safe_root(root):
            return {"error": "root not permitted"}
        allowed.append(_ensure_trailing_sep(os.path.abspath(os.path.expanduser(root))))
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


def write_file(path: str, content: str) -> dict:
    if not isinstance(content, str):
        return {"error": "content must be a string"}
    encoded = content.encode("utf-8")
    if len(encoded) > FILE_WRITE_LIMIT:
        return {"error": f"content exceeds {FILE_WRITE_LIMIT} bytes"}
    abs_path = os.path.abspath(os.path.expanduser(path))
    allowed = [_ensure_trailing_sep(p) for p in _WRITE_ALLOWED_PREFIXES]
    if not any(abs_path.startswith(p) for p in allowed):
        return {"error": "path not permitted"}
    try:
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(encoded)
        return {"ok": True, "path": abs_path, "size_bytes": len(encoded)}
    except Exception as e:
        return {"error": str(e)}


def clone_repo(url: str) -> dict:
    if not isinstance(url, str) or not _GITHUB_URL_RE.match(url):
        return {"error": "only https://github.com/<owner>/<repo> URLs are allowed"}
    os.makedirs(TOOLS_DIR, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix=CLONE_PREFIX, dir=TOOLS_DIR)
    target = os.path.join(tmp_dir, "target")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--", url, target],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return {"error": f"git clone failed: {proc.stderr.strip()[:200]}"}
        return {"path": target, "cleanup_path": tmp_dir}
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return {"error": str(e)}


_SSRF_BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal"}


def _is_safe_remote_url(url: str) -> tuple[bool, str]:
    """SSRF guard: allow only https:// to public, resolvable hosts."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"unparseable URL: {e}"
    if parsed.scheme != "https":
        return False, "only https:// URLs are allowed"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "missing hostname"
    if host in _SSRF_BLOCKED_HOSTNAMES:
        return False, f"blocked hostname: {host}"
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    for fam, _, _, _, sockaddr in addrs:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            return False, f"unresolvable address: {sockaddr}"
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False, f"blocked address: {ip}"
    return True, ""


class _SsrfSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates the target of every HTTP redirect before following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ok, reason = _is_safe_remote_url(newurl)
        if not ok:
            raise urllib.error.URLError(f"unsafe redirect to {newurl!r}: {reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SSRF_SAFE_OPENER = urllib.request.build_opener(_SsrfSafeRedirectHandler())


def _safe_extract_zip(zip_path: str, target_dir: str) -> dict | None:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = zf.infolist()
            if len(members) > ZIP_MEMBER_LIMIT:
                return {"error": f"archive has {len(members)} entries (limit {ZIP_MEMBER_LIMIT})"}
            total = 0
            for m in members:
                total += m.file_size
                if total > ZIP_UNCOMPRESSED_LIMIT:
                    return {"error": f"uncompressed size exceeds {ZIP_UNCOMPRESSED_LIMIT} bytes"}
                if m.file_size > 0 and m.compress_size > 0 and m.file_size / m.compress_size > 200:
                    return {"error": f"suspicious compression ratio for {m.filename!r}"}
                name = m.filename
                if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    return {"error": f"unsafe archive entry: {name!r}"}
                dest = os.path.realpath(os.path.join(target_dir, name))
                if not dest.startswith(os.path.realpath(target_dir) + os.sep) and dest != os.path.realpath(target_dir):
                    return {"error": f"archive entry escapes target dir: {name!r}"}
            zf.extractall(target_dir)
    except zipfile.BadZipFile:
        return {"error": "not a valid zip file"}
    except Exception as e:
        return {"error": str(e)}
    return None


def extract_zip(source: str) -> dict:
    if not isinstance(source, str) or not source:
        return {"error": "source must be a non-empty string"}

    os.makedirs(TOOLS_DIR, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix=CLONE_PREFIX, dir=TOOLS_DIR)
    target = os.path.join(tmp_dir, "target")
    os.makedirs(target, exist_ok=True)

    try:
        if source.startswith(("http://", "https://")):
            if not source.lower().split("?", 1)[0].endswith(".zip"):
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": "URL must point to a .zip file"}
            ok, reason = _is_safe_remote_url(source)
            if not ok:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": f"URL rejected: {reason}"}
            zip_path = os.path.join(tmp_dir, "download.zip")
            try:
                with _SSRF_SAFE_OPENER.open(source, timeout=60) as resp:
                    written = 0
                    with open(zip_path, "wb") as out:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > ZIP_DOWNLOAD_LIMIT:
                                shutil.rmtree(tmp_dir, ignore_errors=True)
                                return {"error": f"download exceeds {ZIP_DOWNLOAD_LIMIT} bytes"}
                            out.write(chunk)
            except Exception as e:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": f"download failed: {e}"}
        else:
            abs_src = os.path.abspath(os.path.expanduser(source))
            if not _is_safe_root(abs_src):
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": "source path not permitted"}
            if not abs_src.lower().endswith(".zip"):
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": "source must be a .zip file"}
            if not os.path.isfile(abs_src):
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return {"error": "source file not found"}
            zip_path = abs_src

        err = _safe_extract_zip(zip_path, target)
        if err:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return err
        return {"path": target, "cleanup_path": tmp_dir}
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return {"error": str(e)}


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "clean": "none",
}


_TRIVY_SEVERITY_NORMALISE = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def normalize_trivy(results: dict) -> dict:
    """Flatten raw Trivy `fs --format json` output into the canonical finding shape
    used by to_sarif and the rest of the pipeline.

    Accepts the dict returned by scan_directory (under `results`) and returns
    `{"findings": [...]}`. Each finding has `category`, `severity`, `file`, `line`,
    `description`, `snippet`, and `detected_by: "Trivy"`.
    """
    findings: list = []
    if not isinstance(results, dict):
        return {"findings": []}

    for r in results.get("Results", []) or []:
        target = r.get("Target") or ""

        for v in r.get("Vulnerabilities", []) or []:
            sev = _TRIVY_SEVERITY_NORMALISE.get(str(v.get("Severity") or "").upper(), "medium")
            vid = v.get("VulnerabilityID") or "CVE-UNKNOWN"
            pkg = v.get("PkgName") or ""
            installed = v.get("InstalledVersion") or ""
            title = v.get("Title") or v.get("Description") or ""
            description = f"{vid} in {pkg}@{installed}".strip() + (f" — {title[:160]}" if title else "")
            findings.append({
                "category": "SUPPLY_CHAIN",
                "severity": sev,
                "file": target,
                "line": v.get("Layer", {}).get("DiffID", 0) if isinstance(v.get("Layer"), dict) else 0,
                "description": description,
                "snippet": f"{pkg}@{installed}",
                "detected_by": "Trivy",
            })

        for s in r.get("Secrets", []) or []:
            sev = _TRIVY_SEVERITY_NORMALISE.get(str(s.get("Severity") or "").upper(), "high")
            rule = s.get("RuleID") or s.get("Title") or "secret"
            findings.append({
                "category": "SECRET_LEAKAGE",
                "severity": sev,
                "file": target,
                "line": s.get("StartLine") or 0,
                "description": f"Trivy secret rule {rule}: {s.get('Title') or ''}".strip(),
                "snippet": (s.get("Match") or "")[:200],
                "detected_by": "Trivy",
            })

        for m in r.get("Misconfigurations", []) or []:
            sev = _TRIVY_SEVERITY_NORMALISE.get(str(m.get("Severity") or "").upper(), "medium")
            findings.append({
                "category": "PERMISSION_ABUSE",
                "severity": sev,
                "file": target,
                "line": (m.get("CauseMetadata") or {}).get("StartLine") or 0,
                "description": f"{m.get('ID') or 'MISCONFIG'}: {m.get('Title') or m.get('Description') or ''}",
                "snippet": (m.get("Resolution") or "")[:200],
                "detected_by": "Trivy",
            })

    return {"findings": findings}


# --- Catalog freshness aggregation ----------------------------------------
# `catalogs_status` is the single canonical source of "which threat-intel and
# rule catalogs is this scan consulting, and how fresh is each?" that the
# skill renders into every report header. Adapters added in future (e.g.
# Bumblebee) should plug in here so the user always sees one consolidated
# block at the top of the report.

_TRIVY_VERSION_RE = re.compile(r"^Version:\s*(\S+)", re.M)
_TRIVY_DB_UPDATED_RE = re.compile(r"UpdatedAt:\s*([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9:.]+)")


def _trivy_status() -> dict:
    """Inspect the locally-installed Trivy binary (if any). Read-only — does
    not auto-install. Never blocks on network."""
    trivy_bin = shutil.which("trivy")
    if not trivy_bin and os.path.exists(TOOLS_TRIVY):
        trivy_bin = TOOLS_TRIVY
    if not trivy_bin:
        return {
            "source": "trivy",
            "name": "Trivy CVE / secret scanner",
            "mode": "managed_binary",
            "available": False,
            "license": "Apache-2.0",
            "license_url": "https://github.com/aquasecurity/trivy/blob/main/LICENSE",
            "reason": "Trivy not installed — will be auto-installed on first scan_directory call",
        }
    info: dict = {
        "source": "trivy",
        "name": "Trivy CVE / secret scanner",
        "mode": "managed_binary",
        "available": True,
        "binary_path": trivy_bin,
        "license": "Apache-2.0",
        "license_url": "https://github.com/aquasecurity/trivy/blob/main/LICENSE",
        "attribution": "© Aqua Security, Apache-2.0",
        "note": "self-updating CVE / secret database — no manual refresh needed",
    }
    try:
        proc = subprocess.run([trivy_bin, "--version"], capture_output=True, text=True, timeout=10)
        out = (proc.stdout or "") + (proc.stderr or "")
        m = _TRIVY_VERSION_RE.search(out)
        if m:
            info["binary_version"] = m.group(1)
        m = _TRIVY_DB_UPDATED_RE.search(out)
        if m:
            info["db_updated_at"] = m.group(1)
    except Exception as e:
        info["version_probe_error"] = str(e)
    return info


def _osv_status() -> dict:
    """OSV.dev is a live HTTPS API — there's nothing to cache locally. We
    return a static descriptor for the report header."""
    return {
        "source": "osv",
        "name": "OSV.dev vulnerability database",
        "mode": "live_api",
        "available": True,
        "endpoint": "https://api.osv.dev/v1/query",
        "license": "Apache-2.0 (engine); upstream advisory licenses per entry",
        "license_url": "https://github.com/google/osv.dev/blob/master/LICENSE",
        "attribution": "© Google, Apache-2.0",
        "note": "queried live by check_osv; degrades silently if the API is unreachable",
    }


def _atr_status() -> dict:
    """Wrap atr_catalog.catalog_status() with the canonical descriptor shape
    expected by catalogs_status consumers."""
    base = atr_catalog.catalog_status()
    descriptor = {
        "source": "atr",
        "name": "Agent Threat Rules (ATR)",
        "mode": "local_catalog",
        "pin": atr_catalog.ATR_PIN,
        "license": atr_catalog.LICENSE,
        "license_url": atr_catalog.LICENSE_URL,
        "attribution": atr_catalog.ATTRIBUTION,
    }
    descriptor.update(base)
    if not base.get("available"):
        descriptor.setdefault("hint", "run atr_update to populate the catalog")
    return descriptor


def catalogs_status() -> dict:
    """Aggregated freshness status for every catalog / source that contributes
    to scan findings. Used by report headers. Never blocks on network: each
    sub-probe is local-only (file reads, locally-installed binary version
    probe) — the only thing that runs an external HTTP call is the user-
    initiated atr_update."""
    return {
        "catalogs": [
            _atr_status(),
            _osv_status(),
            _trivy_status(),
        ],
    }


def to_sarif(findings: list, scan_root: str | None = None) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings or []:
        cat = str(f.get("category") or "UNCATEGORIZED")
        sev = str(f.get("severity") or "medium").lower()
        if cat not in rules:
            rules[cat] = {
                "id": cat,
                "name": cat,
                "shortDescription": {"text": cat.replace("_", " ").title()},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "warning")},
            }
        location: dict = {}
        file_uri = f.get("file") or f.get("path")
        if file_uri:
            location["physicalLocation"] = {
                "artifactLocation": {"uri": str(file_uri)},
            }
            line = f.get("line")
            if isinstance(line, int) and line > 0:
                location["physicalLocation"]["region"] = {"startLine": line}
        result = {
            "ruleId": cat,
            "level": _SARIF_LEVEL.get(sev, "warning"),
            "message": {"text": str(f.get("description") or "")},
        }
        if location:
            result["locations"] = [location]
        snippet = f.get("snippet")
        if snippet:
            result["properties"] = {"snippet": str(snippet), "severity": sev}
        else:
            result["properties"] = {"severity": sev}
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "tomofound",
                "informationUri": "https://github.com/rotoyang/tomofound",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    if scan_root:
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": str(scan_root)}}

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def _load_prompt_source() -> str:
    for candidate in _PROMPT_SOURCE_CANDIDATES:
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                return f.read()
    raise FileNotFoundError(
        f"prompt source not found in any of: {_PROMPT_SOURCE_CANDIDATES}"
    )


def _strip_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    if end < 0:
        return text
    rest = text[end + 4:]
    return rest.lstrip("\n")


def render_prompt(arguments: dict | None = None) -> str:
    body = _strip_frontmatter(_load_prompt_source())
    args_value = ""
    if arguments:
        args_value = str(arguments.get("args", "") or "")
    return body.replace("ARGUMENTS", args_value) if args_value else body


def cleanup_clone(path: str) -> dict:
    abs_path = os.path.abspath(os.path.expanduser(path))
    tools_prefix = _ensure_trailing_sep(TOOLS_DIR)
    name = os.path.basename(abs_path.rstrip(os.sep))
    if not abs_path.startswith(tools_prefix) or not name.startswith(CLONE_PREFIX):
        return {"error": "path not permitted"}
    if not os.path.isdir(abs_path):
        return {"error": "not a directory"}
    shutil.rmtree(abs_path, ignore_errors=True)
    return {"ok": True}


try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    import asyncio
except ImportError:
    Server = None


if Server is not None:
    _server = Server("tomofound")

    @_server.list_prompts()
    async def _list_prompts():
        return [
            types.Prompt(
                name=_PROMPT_NAME,
                description="Scan installed AI tool plugins, skills, and connectors (Claude Code, Gemini, Codex) for secrets, backdoors, data exfiltration, supply-chain CVEs, and prompt injection.",
                arguments=[
                    types.PromptArgument(
                        name="args",
                        description="Optional. Same shape as the slash-command tail: a local path, a https://github.com/... URL, or '--target claude|gemini|openai'. Empty = scan all installed extensions.",
                        required=False,
                    ),
                ],
            ),
        ]

    @_server.get_prompt()
    async def _get_prompt(name: str, arguments: dict | None = None):
        if name != _PROMPT_NAME:
            raise ValueError(f"Unknown prompt: {name}")
        body = render_prompt(arguments)
        return types.GetPromptResult(
            description="tomofound security-scan checklist",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=body),
                ),
            ],
        )

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
                description="Discover all scannable AI tool extension files on the host filesystem.",
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
                            "description": "Custom scan root — required for paths outside ~/.claude, ~/.gemini, ~/.codex. Must resolve under HOME or system temp; ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker are blocked.",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="write_file",
                description="Write a file to the host filesystem. Only paths under ~/.tomofound/ are allowed (for scan reports and temp data). UTF-8, max 8 MB.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute target path"},
                        "content": {"type": "string", "description": "File content (UTF-8 text)"},
                    },
                    "required": ["path", "content"],
                },
            ),
            types.Tool(
                name="clone_repo",
                description="Shallow-clone a public GitHub repository into a server-managed temp directory under ~/.tomofound/tools/. Returns the target path and a cleanup_path for cleanup_clone.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "https://github.com/<owner>/<repo>[.git] — only HTTPS GitHub URLs allowed",
                        },
                    },
                    "required": ["url"],
                },
            ),
            types.Tool(
                name="cleanup_clone",
                description="Remove a temp directory previously created by clone_repo or extract_zip. Only directories named tomofound-scan-* under ~/.tomofound/tools/ are accepted.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "cleanup_path returned by clone_repo or extract_zip"},
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="extract_zip",
                description="Extract a .zip archive (local path or http(s) URL ending in .zip) into a server-managed temp directory under ~/.tomofound/tools/ for pre-installation scanning. Returns the extracted target path and a cleanup_path for cleanup_clone. Rejects zip slip, oversized archives (>200 MB uncompressed), and archives with >10000 entries.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": "Either an absolute local path to a .zip file or an https://.../something.zip URL.",
                        },
                    },
                    "required": ["source"],
                },
            ),
            types.Tool(
                name="analyze_python",
                description="Run AST + lightweight taint-tracking analysis on Python files. Flags eval / exec / pickle.loads / subprocess shell=True / dynamic getattr, and reports when tainted data (env vars, sys.argv, input(), os.environ, requests.get, urlopen, MCP handler params) flows into a sink. Accepts a single .py file or a directory; directories are walked recursively. Returns { findings, files_analyzed, skipped }.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to a .py file or a directory containing Python sources.",
                        },
                    },
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="to_sarif",
                description="Convert a list of standardised tomofound findings into a SARIF 2.1.0 document for CI/CD integration. Each finding object should have category, severity (critical|high|medium|low), file, line, description, and optional snippet.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "description": "List of findings produced by the scan.",
                            "items": {"type": "object"},
                        },
                        "scan_root": {
                            "type": "string",
                            "description": "Optional. Base URI for findings' file paths.",
                        },
                    },
                    "required": ["findings"],
                },
            ),
            types.Tool(
                name="normalize_trivy",
                description="Convert raw Trivy `fs --format json` output (as returned by scan_directory.results) into the standard finding shape used by to_sarif and the rest of the pipeline. Returns {findings: [...]} with category, severity, file, line, description, snippet, detected_by='Trivy'.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "results": {
                            "type": "object",
                            "description": "Raw Trivy JSON output (the `results` field from scan_directory's return).",
                        },
                    },
                    "required": ["results"],
                },
            ),
            types.Tool(
                name="atr_update",
                description="Download and cache the pinned Agent Threat Rules (ATR) catalog locally at ~/.tomofound/catalogs/atr/. User-initiated only — never auto-run. Verifies the upstream LICENSE is still MIT before trusting the tarball, extracts only the rules/ subtree and LICENSE, parses YAML rules into a regex catalog. Returns {ok, version, rules_compiled, categories, tarball_sha256} on success or {error} on any failure (previous cache is preserved).",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="atr_match",
                description="Run the cached ATR regex catalog against scan-target content. Returns {findings, rules_evaluated} where each finding carries provenance.source='atr', rule_id, catalog_version, and upstream references (OWASP Agentic, MITRE ATLAS, CVE). Offline — never blocks on network. If the catalog isn't cached yet, returns {findings: [], catalog_missing: true} and the report header should advise the user to run atr_update.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "The scan-target content (skill markdown body, MCP exchange transcript, prompt template, ...). Matched as a single string.",
                        },
                        "file_hint": {
                            "type": "string",
                            "description": "Optional path to attribute findings to — copied into each finding's `file` field for downstream report rendering.",
                        },
                    },
                    "required": ["content"],
                },
            ),
            types.Tool(
                name="atr_status",
                description="Read-only check of the local ATR catalog state: version, rule count, license, attribution string. Used by report headers and the user-facing freshness display. Never blocks on network.",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="catalogs_status",
                description="Aggregated freshness status for every catalog / source the scanner consults — ATR (local), OSV (live API), Trivy (managed binary). Returns {catalogs: [{source, name, mode, available, version?, license, attribution, ...}, ...]}. The skill renders this into every scan report's header so the user can see at a glance what catalogs were used, what version, and what license. Never blocks on network — each probe is local-only.",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @_server.call_tool()
    async def _call_tool(name: str, arguments: dict):
        if name == "scan_directory":
            path = arguments["path"]
            scanners = arguments.get("scanners", ["vuln", "secret"])
            if not _is_safe_root(path):
                payload = {"trivy_available": False, "results": None,
                           "skipped_reason": "path_not_permitted",
                           "scan_level": None, "scan_level_desc": "path not permitted"}
                return [types.TextContent(type="text", text=json.dumps(payload))]
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

        if name == "write_file":
            result = write_file(
                path=arguments["path"],
                content=arguments["content"],
            )
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "clone_repo":
            result = clone_repo(url=arguments["url"])
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "cleanup_clone":
            result = cleanup_clone(path=arguments["path"])
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "extract_zip":
            result = extract_zip(source=arguments["source"])
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "analyze_python":
            path = arguments["path"]
            if not _is_safe_root(path):
                result = {"error": "path not permitted"}
            else:
                result = analyze_python(path=path)
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "to_sarif":
            result = to_sarif(
                findings=arguments.get("findings", []),
                scan_root=arguments.get("scan_root"),
            )
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "normalize_trivy":
            result = normalize_trivy(results=arguments.get("results") or {})
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "atr_update":
            result = atr_catalog.update_catalog()
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "atr_match":
            result = atr_catalog.match_content(
                content=arguments.get("content") or "",
                file_hint=arguments.get("file_hint"),
            )
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "atr_status":
            result = atr_catalog.catalog_status()
            return [types.TextContent(type="text", text=json.dumps(result))]

        if name == "catalogs_status":
            result = catalogs_status()
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
