import os, sys, json, pytest, zipfile, io
from unittest.mock import patch, MagicMock
import tempfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server.trivy_server import (
    find_or_install_trivy, detect_scan_level, query_osv, discover_targets, read_file,
    write_file, clone_repo, cleanup_clone, _is_safe_root,
    _tag_file, _plugin_from_path, _source_type, _STANDARD_ROOTS, _READ_ALLOWED_PREFIXES,
    _WRITE_ALLOWED_PREFIXES, CLONE_PREFIX, TOOLS_DIR,
    render_prompt, _strip_frontmatter, _load_prompt_source, _PROMPT_NAME,
    extract_zip, to_sarif, ZIP_MEMBER_LIMIT,
)


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


def test_detect_level1_priority_lock_over_manifest():
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


# --- Trivy checksum integrity (regression: the scanner found this on itself) ---

from server.trivy_server import _fetch_trivy_checksums, _hash_file_sha256


class _CapturingUrlopen:
    """Stub urllib.request.urlopen that returns canned bytes per URL prefix.
    Also records every request URL so tests can assert what was fetched."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls = []

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        for prefix, body in self.responses.items():
            if url.startswith(prefix):
                return _CapturingUrlopen._FakeResponse(body)
        raise RuntimeError(f"unexpected URL in test: {url}")

    class _FakeResponse:
        def __init__(self, data):
            self._data = data if isinstance(data, bytes) else data.encode()
            self._offset = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, n=-1):
            if n is None or n < 0:
                chunk = self._data[self._offset:]
                self._offset = len(self._data)
                return chunk
            chunk = self._data[self._offset:self._offset + n]
            self._offset += len(chunk)
            return chunk


def test_fetch_trivy_checksums_parses_published_format():
    # Explicit `+` between every fragment — implicit string concatenation
    # binds tighter than `+ "x" * N` in surprising ways.
    checksums_body = (
        "a" * 64 + "  trivy_0.59.0_macOS-ARM64.tar.gz\n"
        + "b" * 64 + "  trivy_0.59.0_Linux-64bit.tar.gz\n"
        + "# a comment line is skipped\n"
        + "\n"
    )
    stub = _CapturingUrlopen({"https://github.com/aquasecurity/trivy/releases/download/v0.59.0/trivy_0.59.0_checksums.txt": checksums_body})
    with patch("urllib.request.urlopen", stub):
        result = _fetch_trivy_checksums("0.59.0")
    assert result["trivy_0.59.0_macOS-ARM64.tar.gz"] == "a" * 64
    assert result["trivy_0.59.0_Linux-64bit.tar.gz"] == "b" * 64
    assert len(result) == 2


def test_fetch_trivy_checksums_rejects_empty():
    stub = _CapturingUrlopen({"https://github.com/aquasecurity/trivy/releases/download/": "# only comments\n"})
    with patch("urllib.request.urlopen", stub):
        with pytest.raises(RuntimeError, match="unparseable"):
            _fetch_trivy_checksums("0.59.0")


def test_hash_file_sha256_round_trip(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"tomofound")
    actual = _hash_file_sha256(str(p))
    # sha256("tomofound") == known constant — recomputed here for clarity
    import hashlib
    expected = hashlib.sha256(b"tomofound").hexdigest()
    assert actual == expected
    assert len(actual) == 64


def test_find_or_install_trivy_refuses_when_checksums_missing(tmp_path, monkeypatch):
    """If the checksums.txt cannot be fetched we MUST NOT install — better
    LLM-only than an unverified binary. The scanner found exactly this gap
    on its own code; the fix should never regress."""
    monkeypatch.setattr("server.trivy_server.TOOLS_TRIVY", str(tmp_path / "trivy"))
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path))

    release_json = json.dumps({"tag_name": "v0.59.0"}).encode()

    def _urlopen(url, timeout=None):
        if "/releases/latest" in url:
            return _CapturingUrlopen._FakeResponse(release_json)
        if "/checksums.txt" in url:
            raise RuntimeError("checksums fetch failed (simulated)")
        raise RuntimeError(f"unexpected: {url}")

    with patch("shutil.which", return_value=None), \
         patch("urllib.request.urlopen", side_effect=_urlopen), \
         patch("platform.system", return_value="Darwin"), \
         patch("platform.machine", return_value="arm64"):
        result = find_or_install_trivy()
    assert result is None


def test_find_or_install_trivy_refuses_on_checksum_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_TRIVY", str(tmp_path / "trivy"))
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path))

    release_json = json.dumps({"tag_name": "v0.59.0"}).encode()
    archive_bytes = b"not the real trivy archive"
    checksums = "z" * 64 + "  trivy_0.59.0_macOS-ARM64.tar.gz\n"  # 'z'*64 won't match

    def _urlopen(url, timeout=None):
        if "/releases/latest" in url:
            return _CapturingUrlopen._FakeResponse(release_json)
        if url.endswith("checksums.txt"):
            return _CapturingUrlopen._FakeResponse(checksums)
        if url.endswith("trivy_0.59.0_macOS-ARM64.tar.gz"):
            return _CapturingUrlopen._FakeResponse(archive_bytes)
        raise RuntimeError(f"unexpected: {url}")

    with patch("shutil.which", return_value=None), \
         patch("urllib.request.urlopen", side_effect=_urlopen), \
         patch("platform.system", return_value="Darwin"), \
         patch("platform.machine", return_value="arm64"):
        result = find_or_install_trivy()
    assert result is None
    # The binary must NOT have been installed.
    assert not os.path.exists(str(tmp_path / "trivy"))


def test_find_or_install_trivy_refuses_when_archive_not_in_checksums(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_TRIVY", str(tmp_path / "trivy"))
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path))

    release_json = json.dumps({"tag_name": "v0.59.0"}).encode()
    # Checksums file lists a DIFFERENT archive — ours isn't there.
    checksums = "a" * 64 + "  trivy_0.59.0_Linux-64bit.tar.gz\n"

    def _urlopen(url, timeout=None):
        if "/releases/latest" in url:
            return _CapturingUrlopen._FakeResponse(release_json)
        if url.endswith("checksums.txt"):
            return _CapturingUrlopen._FakeResponse(checksums)
        raise RuntimeError(f"should not have downloaded archive: {url}")

    with patch("shutil.which", return_value=None), \
         patch("urllib.request.urlopen", side_effect=_urlopen), \
         patch("platform.system", return_value="Darwin"), \
         patch("platform.machine", return_value="arm64"):
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
    content = "x" * (1024 * 1024 + 1)
    f.write_text(content)
    result = read_file(str(f), root=str(tmp_path))
    assert result["truncated"] is True
    assert result["size_bytes"] == len(content)
    assert len(result["content"]) == 1024 * 1024


def test_read_file_rejects_unpermitted_path(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("sensitive")
    result = read_file(str(f))
    assert "error" in result
    assert "not permitted" in result["error"]


def test_read_file_returns_error_for_missing_file(tmp_path):
    result = read_file(str(tmp_path / "nonexistent.txt"), root=str(tmp_path))
    assert "error" in result
    assert "not found" in result["error"]


# --- platform path coverage ---

def test_standard_roots_cover_claude_extension_dirs():
    claude = _STANDARD_ROOTS["claude"]
    assert any(r.endswith("/.claude/plugins/cache") for r in claude)
    assert any(r.endswith("/.claude/plugins/repos") for r in claude)
    assert any(r.endswith("/.claude/skills") for r in claude)
    assert any(r.endswith("/.claude/agents") for r in claude)
    assert any(r.endswith("/.claude/commands") for r in claude)
    assert any(r.endswith("/.claude/.mcp.json") for r in claude)


def test_standard_roots_cover_gemini_extension_dirs():
    gemini = _STANDARD_ROOTS["gemini"]
    assert any(r.endswith("/.gemini/extensions") for r in gemini)
    assert any(r.endswith("/.gemini/config/plugins") for r in gemini)
    assert any(r.endswith("/.gemini/commands") for r in gemini)
    assert any(r.endswith("/.gemini/settings.json") for r in gemini)


def test_standard_roots_openai_points_at_codex():
    openai = _STANDARD_ROOTS["openai"]
    assert all("/.codex/" in r or r.endswith("/.codex/AGENTS.md") for r in openai)
    assert not any("/.openai/" in r for r in openai)
    assert any(r.endswith("/.codex/auth.json") for r in openai)
    assert any(r.endswith("/.codex/config.toml") for r in openai)
    assert any(r.endswith("/.codex/skills") for r in openai)
    assert any(r.endswith("/.codex/plugins/cache") for r in openai)
    assert any(r.endswith("/.codex/prompts") for r in openai)


def test_read_allowed_prefixes_match_standard_roots():
    assert any(p.endswith("/.codex/") for p in _READ_ALLOWED_PREFIXES)
    assert not any(p.endswith("/.openai/") for p in _READ_ALLOWED_PREFIXES)


def test_tag_file_treats_agents_md_as_skill(tmp_path):
    f = tmp_path / "AGENTS.md"
    f.write_text("")
    assert _tag_file(str(f)) == "SKILL"


def test_tag_file_treats_claude_agents_dir_as_skill():
    p = os.path.expanduser("~/.claude/agents/my-agent.md")
    assert _tag_file(p) == "SKILL"


def test_tag_file_treats_codex_prompts_as_skill():
    p = os.path.expanduser("~/.codex/prompts/p.md")
    assert _tag_file(p) == "SKILL"


def test_tag_file_treats_gemini_commands_toml_as_skill():
    p = os.path.expanduser("~/.gemini/commands/foo.toml")
    assert _tag_file(p) == "SKILL"


def test_tag_file_codex_config_toml_is_config():
    p = os.path.expanduser("~/.codex/config.toml")
    assert _tag_file(p) == "CONFIG"


def test_source_type_gemini_extension_is_plugin():
    p = os.path.expanduser("~/.gemini/extensions/foo/server.ts")
    assert _source_type(p, "CODE") == "plugin"


def test_source_type_gemini_config_plugin_is_plugin():
    p = os.path.expanduser("~/.gemini/config/plugins/foo/server.ts")
    assert _source_type(p, "CODE") == "plugin"


def test_source_type_codex_cached_plugin_is_plugin():
    p = os.path.expanduser("~/.codex/plugins/cache/openai-bundled/browser/1.0.0/server.ts")
    assert _source_type(p, "CODE") == "plugin"


def test_plugin_from_path_gemini_extension():
    p = os.path.expanduser("~/.gemini/extensions/foo/server.ts")
    assert _plugin_from_path(p) == "foo"


def test_plugin_from_path_gemini_config_plugin():
    p = os.path.expanduser("~/.gemini/config/plugins/foo/skills/bar/SKILL.md")
    assert _plugin_from_path(p) == "foo"


def test_plugin_from_path_codex_cached_plugin():
    p = os.path.expanduser("~/.codex/plugins/cache/openai-bundled/browser/1.0.0/server.ts")
    assert _plugin_from_path(p) == "openai-bundled/browser"


def test_plugin_from_path_claude_agents_returns_stem():
    p = os.path.expanduser("~/.claude/agents/reviewer.md")
    assert _plugin_from_path(p) == "reviewer"


# --- _is_safe_root ---

def test_is_safe_root_accepts_home_subdir(tmp_path):
    assert _is_safe_root(str(tmp_path)) is True


def test_is_safe_root_accepts_home_itself():
    assert _is_safe_root(os.path.expanduser("~")) is True


def test_is_safe_root_rejects_etc():
    assert _is_safe_root("/etc") is False


def test_is_safe_root_rejects_root_filesystem():
    assert _is_safe_root("/") is False


def test_is_safe_root_rejects_ssh():
    assert _is_safe_root(os.path.expanduser("~/.ssh")) is False


def test_is_safe_root_rejects_aws():
    assert _is_safe_root(os.path.expanduser("~/.aws")) is False


def test_is_safe_root_rejects_gnupg_subpath():
    assert _is_safe_root(os.path.expanduser("~/.gnupg/private-keys-v1.d")) is False


# --- read_file with sensitive root ---

def test_read_file_rejects_sensitive_root_even_under_home():
    result = read_file(os.path.expanduser("~/.ssh/id_rsa"),
                       root=os.path.expanduser("~/.ssh"))
    assert "error" in result
    assert "not permitted" in result["error"]


def test_read_file_root_does_not_accidentally_match_prefix(tmp_path):
    # Regression: previously read_file used startswith without trailing sep,
    # so root=/tmp/foo would also grant access to /tmp/foobar/secret.
    sibling = tmp_path.parent / (tmp_path.name + "_sibling")
    sibling.mkdir()
    (sibling / "secret.txt").write_text("nope")
    result = read_file(str(sibling / "secret.txt"), root=str(tmp_path))
    assert "error" in result
    assert "not permitted" in result["error"]


# --- write_file ---

def test_write_file_rejects_unpermitted_path(tmp_path):
    result = write_file(str(tmp_path / "out.md"), "hi")
    assert "error" in result
    assert "not permitted" in result["error"]


def test_write_file_writes_to_reports_dir(tmp_path, monkeypatch):
    fake_reports = tmp_path / "tomofound"
    monkeypatch.setattr(
        "server.trivy_server._WRITE_ALLOWED_PREFIXES",
        [str(fake_reports) + os.sep],
    )
    target = fake_reports / "reports" / "r.md"
    result = write_file(str(target), "# report\n")
    assert result.get("ok") is True
    assert target.read_text() == "# report\n"


def test_write_file_rejects_oversized_content(tmp_path, monkeypatch):
    fake_reports = tmp_path / "tomofound"
    monkeypatch.setattr(
        "server.trivy_server._WRITE_ALLOWED_PREFIXES",
        [str(fake_reports) + os.sep],
    )
    big = "x" * (8 * 1024 * 1024 + 1)
    result = write_file(str(fake_reports / "r.md"), big)
    assert "error" in result
    assert "exceeds" in result["error"]


# --- clone_repo ---

def test_clone_repo_rejects_non_github_url():
    result = clone_repo("https://evil.example.com/foo/bar")
    assert "error" in result


def test_clone_repo_rejects_shell_metacharacters():
    result = clone_repo("https://github.com/foo/bar; rm -rf ~")
    assert "error" in result


def test_clone_repo_rejects_path_traversal():
    result = clone_repo("https://github.com/../etc/passwd")
    assert "error" in result


def test_clone_repo_accepts_valid_url_format():
    # Don't actually clone — just verify the URL passes validation
    # by mocking subprocess.run to return success.
    with patch("server.trivy_server.subprocess.run") as mock_run, \
         patch("server.trivy_server.tempfile.mkdtemp", return_value="/tmp/fake-tomofound-scan-x"):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = clone_repo("https://github.com/foo/bar")
        assert "error" not in result
        assert result["path"].endswith("target")
        args = mock_run.call_args[0][0]
        # Must use list args and `--` separator (no shell injection)
        assert args[:4] == ["git", "clone", "--depth", "1"]
        assert "--" in args


# --- cleanup_clone ---

def test_cleanup_clone_removes_tomofound_dir(tmp_path, monkeypatch):
    fake_tools = tmp_path
    target = fake_tools / f"{CLONE_PREFIX}abc"
    target.mkdir()
    (target / "marker").write_text("x")
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(fake_tools))
    result = cleanup_clone(str(target))
    assert result.get("ok") is True
    assert not target.exists()


def test_cleanup_clone_rejects_non_tomofound_dir(tmp_path, monkeypatch):
    target = tmp_path / "random-dir"
    target.mkdir()
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path))
    result = cleanup_clone(str(target))
    assert "error" in result
    assert target.exists()


def test_cleanup_clone_rejects_outside_tools_dir(tmp_path, monkeypatch):
    elsewhere = tmp_path / f"{CLONE_PREFIX}escaped"
    elsewhere.mkdir()
    fake_tools = tmp_path / "tools"
    fake_tools.mkdir()
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(fake_tools))
    result = cleanup_clone(str(elsewhere))
    assert "error" in result
    assert elsewhere.exists()


# --- discover_targets path validation ---

def test_discover_targets_rejects_sensitive_path():
    result = discover_targets(path="/etc")
    assert result.get("error") == "path not permitted"
    assert result["items"] == []


# --- prompt loading ---

def test_strip_frontmatter_removes_yaml_block():
    text = "---\nname: foo\ndescription: bar\n---\n\nactual body\n"
    assert _strip_frontmatter(text) == "actual body\n"


def test_strip_frontmatter_passthrough_when_no_block():
    text = "no frontmatter here\n"
    assert _strip_frontmatter(text) == text


def test_load_prompt_source_finds_skill_file():
    body = _load_prompt_source()
    assert "Checklist" in body or "checklist" in body
    assert "discover_targets" in body


def test_render_prompt_default_keeps_arguments_placeholder():
    body = render_prompt()
    assert "ARGUMENTS" in body


def test_render_prompt_substitutes_args():
    body = render_prompt({"args": "--target claude"})
    assert "ARGUMENTS" not in body
    assert "--target claude" in body


def test_prompt_name_constant():
    assert _PROMPT_NAME == "security_scan"


# --- extract_zip ---

def _make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


def test_extract_zip_local_ok(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    zip_path = tmp_path / "skill.zip"
    _make_zip(zip_path, {"SKILL.md": "# hello\n", "src/foo.py": "print(1)\n"})

    result = extract_zip(str(zip_path))
    assert "path" in result, result
    assert os.path.isdir(result["path"])
    assert os.path.exists(os.path.join(result["path"], "SKILL.md"))
    assert os.path.exists(os.path.join(result["path"], "src", "foo.py"))
    shutil.rmtree(result["cleanup_path"], ignore_errors=True)


def test_extract_zip_rejects_non_zip_extension(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    txt = tmp_path / "data.txt"
    txt.write_text("hi")
    result = extract_zip(str(txt))
    assert "error" in result and ".zip" in result["error"]


def test_extract_zip_rejects_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    result = extract_zip(str(tmp_path / "missing.zip"))
    assert "error" in result


def test_extract_zip_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    zip_path = tmp_path / "evil.zip"
    _make_zip(zip_path, {"../escape.txt": "pwned"})
    result = extract_zip(str(zip_path))
    assert "error" in result and "unsafe" in result["error"].lower()


def test_extract_zip_rejects_absolute_path_entry(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    zip_path = tmp_path / "evil.zip"
    _make_zip(zip_path, {"/etc/evil": "pwned"})
    result = extract_zip(str(zip_path))
    assert "error" in result


def test_extract_zip_rejects_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr("server.trivy_server.ZIP_MEMBER_LIMIT", 2)
    zip_path = tmp_path / "big.zip"
    _make_zip(zip_path, {"a": "1", "b": "2", "c": "3"})
    result = extract_zip(str(zip_path))
    assert "error" in result and "entries" in result["error"]


def test_extract_zip_rejects_bad_zip(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    fake = tmp_path / "fake.zip"
    fake.write_text("not actually a zip")
    result = extract_zip(str(fake))
    assert "error" in result


def test_extract_zip_rejects_url_without_zip_suffix(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    result = extract_zip("https://example.com/something.tar.gz")
    assert "error" in result and ".zip" in result["error"]


def test_extract_zip_rejects_unsafe_local_path(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    result = extract_zip("/etc/shadow.zip")
    assert "error" in result


def test_extract_zip_rejects_empty_source():
    assert "error" in extract_zip("")


# --- to_sarif ---

def test_to_sarif_basic_structure():
    findings = [{
        "category": "BACKDOOR",
        "severity": "critical",
        "file": "src/evil.py",
        "line": 7,
        "description": "Uses eval on remote input",
        "snippet": "eval(requests.get(url).text)",
    }]
    doc = to_sarif(findings)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "tomofound"
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "BACKDOOR" for r in rules)
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "BACKDOOR"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/evil.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert res["properties"]["snippet"] == "eval(requests.get(url).text)"


def test_to_sarif_severity_mapping():
    findings = [
        {"category": "A", "severity": "critical", "description": "c"},
        {"category": "B", "severity": "high", "description": "h"},
        {"category": "C", "severity": "medium", "description": "m"},
        {"category": "D", "severity": "low", "description": "l"},
    ]
    results = to_sarif(findings)["runs"][0]["results"]
    levels = [r["level"] for r in results]
    assert levels == ["error", "error", "warning", "note"]


def test_to_sarif_empty_findings():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_to_sarif_finding_without_file():
    doc = to_sarif([{
        "category": "PROMPT_INJECTION",
        "severity": "high",
        "description": "Skill-level injection — no file context",
    }])
    res = doc["runs"][0]["results"][0]
    assert "locations" not in res
    assert res["ruleId"] == "PROMPT_INJECTION"


def test_to_sarif_with_scan_root():
    doc = to_sarif([{"category": "X", "severity": "low", "description": "d"}],
                   scan_root="/tmp/scan")
    assert doc["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"] == "/tmp/scan"


# --- SSRF defense for extract_zip ---

from server.trivy_server import _is_safe_remote_url, normalize_trivy


def test_safe_url_rejects_http_scheme():
    ok, reason = _is_safe_remote_url("http://example.com/x.zip")
    assert not ok and "https" in reason


def test_safe_url_rejects_localhost_name():
    ok, reason = _is_safe_remote_url("https://localhost/x.zip")
    assert not ok and "localhost" in reason


def test_safe_url_rejects_loopback_literal():
    ok, reason = _is_safe_remote_url("https://127.0.0.1/x.zip")
    assert not ok and "127.0.0.1" in reason


def test_safe_url_rejects_link_local_metadata():
    ok, reason = _is_safe_remote_url("https://169.254.169.254/x.zip")
    assert not ok


def test_safe_url_rejects_private_rfc1918():
    ok, reason = _is_safe_remote_url("https://10.0.0.1/x.zip")
    assert not ok


def test_safe_url_rejects_cloud_metadata_hostname():
    ok, reason = _is_safe_remote_url("https://metadata.google.internal/x.zip")
    assert not ok and "metadata" in reason


def test_safe_url_allows_public_https():
    ok, reason = _is_safe_remote_url("https://github.com/foo/bar.zip")
    assert ok, reason


def test_extract_zip_blocks_http_url(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    result = extract_zip("http://example.com/x.zip")
    assert "error" in result and "https" in result["error"]


def test_extract_zip_blocks_loopback_url(tmp_path, monkeypatch):
    monkeypatch.setattr("server.trivy_server.TOOLS_DIR", str(tmp_path / "tools"))
    result = extract_zip("https://127.0.0.1/x.zip")
    assert "error" in result and "127.0.0.1" in result["error"]


# --- normalize_trivy ---

def test_normalize_trivy_vulnerability():
    raw = {"Results": [{
        "Target": "package-lock.json",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-1234",
            "PkgName": "lodash",
            "InstalledVersion": "4.17.20",
            "Severity": "HIGH",
            "Title": "Prototype pollution",
        }],
    }]}
    out = normalize_trivy(raw)
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "SUPPLY_CHAIN"
    assert f["severity"] == "high"
    assert f["file"] == "package-lock.json"
    assert "CVE-2024-1234" in f["description"]
    assert "lodash" in f["description"]
    assert f["detected_by"] == "Trivy"


def test_normalize_trivy_secret():
    raw = {"Results": [{
        "Target": "config.py",
        "Secrets": [{
            "RuleID": "aws-access-key-id",
            "Title": "AWS access key",
            "Severity": "CRITICAL",
            "StartLine": 42,
            "Match": "AKIA1234567890ABCDEF",
        }],
    }]}
    out = normalize_trivy(raw)
    assert out["findings"][0]["category"] == "SECRET_LEAKAGE"
    assert out["findings"][0]["severity"] == "critical"
    assert out["findings"][0]["line"] == 42


def test_normalize_trivy_misconfiguration():
    raw = {"Results": [{
        "Target": "Dockerfile",
        "Misconfigurations": [{
            "ID": "DS002",
            "Title": "running as root",
            "Severity": "MEDIUM",
            "CauseMetadata": {"StartLine": 5},
        }],
    }]}
    out = normalize_trivy(raw)
    assert out["findings"][0]["category"] == "PERMISSION_ABUSE"
    assert out["findings"][0]["line"] == 5


def test_normalize_trivy_empty():
    assert normalize_trivy({})["findings"] == []
    assert normalize_trivy(None)["findings"] == []


def test_normalize_trivy_unknown_severity_defaults():
    raw = {"Results": [{
        "Target": "x",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-X",
            "PkgName": "p",
            "InstalledVersion": "1",
            "Severity": "WAT",  # not in mapping
        }],
    }]}
    out = normalize_trivy(raw)
    assert out["findings"][0]["severity"] == "medium"


def test_normalize_trivy_into_to_sarif():
    raw = {"Results": [{
        "Target": "package-lock.json",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-1",
            "PkgName": "lodash",
            "InstalledVersion": "1",
            "Severity": "HIGH",
        }],
    }]}
    findings = normalize_trivy(raw)["findings"]
    doc = to_sarif(findings)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "SUPPLY_CHAIN" for r in rules)
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "SUPPLY_CHAIN"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"


# --- catalogs_status ----------------------------------------------------

from server.trivy_server import catalogs_status, _osv_status, _atr_status, _trivy_status


def test_osv_status_static_descriptor():
    s = _osv_status()
    assert s["source"] == "osv"
    assert s["mode"] == "live_api"
    assert s["available"] is True
    assert "google" in s["attribution"].lower()
    assert s["endpoint"].startswith("https://")


def test_atr_status_returns_unavailable_when_uncached(tmp_path, monkeypatch):
    # trivy_server imports atr_catalog as a top-level module (via sys.path
    # injection in trivy_server.py), so we patch through `server.trivy_server.atr_catalog`
    # to hit the same instance the production code calls.
    import server.trivy_server as ts
    monkeypatch.setattr(ts.atr_catalog, "META_PATH", str(tmp_path / "nonexistent.json"))
    s = _atr_status()
    assert s["source"] == "atr"
    assert s["available"] is False
    assert "atr_update" in s["hint"]
    assert s["pin"] == ts.atr_catalog.ATR_PIN
    assert s["license"] == "MIT"


def test_atr_status_surfaces_cached_metadata(tmp_path, monkeypatch):
    import server.trivy_server as ts
    meta = {
        "version": "v3.5.0",
        "rules_compiled": 5,
        "categories": ["prompt-injection"],
        "license": "MIT",
        "attribution": "ATR",
    }
    meta_path = tmp_path / "meta.json"
    meta_path.write_text(json.dumps(meta))
    monkeypatch.setattr(ts.atr_catalog, "META_PATH", str(meta_path))
    s = _atr_status()
    assert s["available"] is True
    assert s["version"] == "v3.5.0"
    assert s["rules_compiled"] == 5
    assert "hint" not in s  # only present when unavailable


def test_trivy_status_when_binary_missing(monkeypatch):
    monkeypatch.setattr("server.trivy_server.shutil.which", lambda _: None)
    monkeypatch.setattr("server.trivy_server.TOOLS_TRIVY", "/nonexistent/trivy")
    s = _trivy_status()
    assert s["source"] == "trivy"
    assert s["available"] is False
    assert "Trivy not installed" in s["reason"]
    assert s["license"] == "Apache-2.0"


def test_trivy_status_parses_version_output(monkeypatch, tmp_path):
    fake_trivy = tmp_path / "trivy"
    fake_trivy.write_text("#!/bin/sh\nexit 0\n")
    fake_trivy.chmod(0o755)
    monkeypatch.setattr("server.trivy_server.shutil.which", lambda _: str(fake_trivy))

    class _FakeCompleted:
        stdout = (
            "Version: 0.59.1\n"
            "Vulnerability DB:\n"
            "  Version: 2\n"
            "  UpdatedAt: 2026-06-19 06:18:08.123 +0000 UTC\n"
        )
        stderr = ""
    monkeypatch.setattr("server.trivy_server.subprocess.run",
                        lambda *a, **k: _FakeCompleted())
    s = _trivy_status()
    assert s["available"] is True
    assert s["binary_version"] == "0.59.1"
    assert "2026-06-19" in s["db_updated_at"]


def test_catalogs_status_includes_all_three_sources(monkeypatch):
    monkeypatch.setattr("server.trivy_server.shutil.which", lambda _: None)
    monkeypatch.setattr("server.trivy_server.TOOLS_TRIVY", "/nonexistent/trivy")
    result = catalogs_status()
    sources = [c["source"] for c in result["catalogs"]]
    assert sources == ["atr", "osv", "trivy"]
    # Every entry must carry an availability flag so renderers can branch
    for c in result["catalogs"]:
        assert "available" in c
        assert "name" in c
        assert "mode" in c


from server.trivy_server import compute_risk_score


def test_compute_risk_score_empty_findings_is_safe():
    r = compute_risk_score([])
    assert r["score"] == 0
    assert r["raw_score"] == 0
    assert r["capped"] is False
    assert r["recommendation"] == "SAFE"
    assert r["badge"] == "✅ SAFE"
    assert r["counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}


def test_compute_risk_score_caution_band():
    r = compute_risk_score([{"severity": "low"}, {"severity": "medium"}])
    assert r["raw_score"] == 4  # 1 + 3
    assert r["score"] == 4
    assert r["recommendation"] == "CAUTION"
    assert r["badge"] == "🔵 CAUTION"


def test_compute_risk_score_high_risk_band():
    # 2 high + 1 medium = 23 → 16-50 band
    r = compute_risk_score([
        {"severity": "high"}, {"severity": "high"}, {"severity": "medium"}
    ])
    assert r["raw_score"] == 23
    assert r["score"] == 23
    assert r["recommendation"] == "HIGH_RISK"
    assert r["badge"] == "⚠️ HIGH RISK"


def test_compute_risk_score_avoid_band():
    # 1 critical + 3 high = 55 → 51-100 band
    r = compute_risk_score([
        {"severity": "critical"},
        {"severity": "high"}, {"severity": "high"}, {"severity": "high"},
    ])
    assert r["raw_score"] == 55
    assert r["score"] == 55
    assert r["capped"] is False
    assert r["recommendation"] == "AVOID"
    assert r["badge"] == "🚫 AVOID"


def test_compute_risk_score_caps_at_100():
    # 5 criticals = 125 raw, capped to 100
    findings = [{"severity": "critical"}] * 5
    r = compute_risk_score(findings)
    assert r["raw_score"] == 125
    assert r["score"] == 100
    assert r["capped"] is True
    assert r["recommendation"] == "AVOID"


def test_compute_risk_score_severity_case_insensitive():
    r = compute_risk_score([{"severity": "HIGH"}, {"severity": "Medium"}])
    assert r["counts"]["high"] == 1
    assert r["counts"]["medium"] == 1
    assert r["raw_score"] == 13


def test_compute_risk_score_ignores_unknown_severity():
    r = compute_risk_score([
        {"severity": "info"},  # not in the weight table
        {"severity": "high"},
        {"severity": ""},
        {},  # missing severity
    ])
    assert r["raw_score"] == 10
    assert r["counts"]["total"] == 1


def test_compute_risk_score_counts_match_findings():
    r = compute_risk_score([
        {"severity": "critical"},
        {"severity": "high"}, {"severity": "high"},
        {"severity": "medium"}, {"severity": "medium"}, {"severity": "medium"},
        {"severity": "low"},
    ])
    assert r["counts"] == {
        "critical": 1, "high": 2, "medium": 3, "low": 1, "total": 7,
    }
    # Weights are part of the response so users can audit the math
    assert r["weights"] == {"critical": 25, "high": 10, "medium": 3, "low": 1}


def test_compute_risk_score_band_boundaries():
    # 15 (top of caution)
    r15 = compute_risk_score([{"severity": "high"}, {"severity": "high"}] +
                              [{"severity": "low"}] * 0 +
                              [{"severity": "low"}] * 0)
    # 2 high = 20 — actually this isn't the boundary; build one explicitly
    fifteen = compute_risk_score([{"severity": "high"}, {"severity": "medium"},
                                   {"severity": "low"}, {"severity": "low"}])
    assert fifteen["raw_score"] == 15
    assert fifteen["recommendation"] == "CAUTION"

    # 16 → HIGH_RISK boundary
    sixteen = compute_risk_score([{"severity": "high"}, {"severity": "medium"},
                                   {"severity": "medium"}])
    assert sixteen["raw_score"] == 16
    assert sixteen["recommendation"] == "HIGH_RISK"

    # 51 → AVOID boundary
    fifty_one = compute_risk_score([{"severity": "critical"},
                                     {"severity": "critical"},
                                     {"severity": "low"}])
    assert fifty_one["raw_score"] == 51
    assert fifty_one["recommendation"] == "AVOID"


def test_compute_risk_score_handles_none_entries():
    # Defensive: callers may include None placeholders mid-list
    r = compute_risk_score([{"severity": "high"}, None, {"severity": "low"}])
    assert r["raw_score"] == 11
