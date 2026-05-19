import os, sys, json, pytest
from unittest.mock import patch, MagicMock
import tempfile, shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from server.trivy_server import find_or_install_trivy, detect_scan_level, query_osv, discover_targets, read_file


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
