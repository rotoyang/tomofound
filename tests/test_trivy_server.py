import os, sys, json, pytest
from unittest.mock import patch, MagicMock
import tempfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server.trivy_server import (
    find_or_install_trivy, detect_scan_level, query_osv, discover_targets, read_file,
    write_file, clone_repo, cleanup_clone, _is_safe_root,
    _tag_file, _plugin_from_path, _source_type, _STANDARD_ROOTS, _READ_ALLOWED_PREFIXES,
    _WRITE_ALLOWED_PREFIXES, CLONE_PREFIX, TOOLS_DIR,
    render_prompt, _strip_frontmatter, _load_prompt_source, _PROMPT_NAME,
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
    assert any(r.endswith("/.gemini/commands") for r in gemini)
    assert any(r.endswith("/.gemini/settings.json") for r in gemini)


def test_standard_roots_openai_points_at_codex():
    openai = _STANDARD_ROOTS["openai"]
    assert all("/.codex/" in r or r.endswith("/.codex/AGENTS.md") for r in openai)
    assert not any("/.openai/" in r for r in openai)
    assert any(r.endswith("/.codex/auth.json") for r in openai)
    assert any(r.endswith("/.codex/config.toml") for r in openai)
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


def test_plugin_from_path_gemini_extension():
    p = os.path.expanduser("~/.gemini/extensions/foo/server.ts")
    assert _plugin_from_path(p) == "foo"


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
