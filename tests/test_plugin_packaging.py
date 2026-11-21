"""Guards the Claude Code plugin packaging: the three places a release version
lives must agree, the marketplace must pin a tag, and the plugin's launch
config must only reach the server through ${CLAUDE_PLUGIN_ROOT}.

Everything here is static and offline. setup.sh is parsed, never executed."""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SETUP_SH = REPO_ROOT / "setup.sh"
PLUGIN_JSON = REPO_ROOT / ".claude-plugin" / "plugin.json"
MARKETPLACE_JSON = REPO_ROOT / ".claude-plugin" / "marketplace.json"
MCP_JSON = REPO_ROOT / ".mcp.json"
HOOKS_JSON = REPO_ROOT / "hooks" / "hooks.json"

ROOT_VAR = "${CLAUDE_PLUGIN_ROOT}"
SERVER_ARG = f"{ROOT_VAR}/server/trivy_server.py"

# Anchored to the start of a line, so the "TOMOFOUND_REF=main" in comments and
# error messages does not match. Only the default-value form is accepted.
_REF_ASSIGNMENT = re.compile(r'^[ \t]*TOMOFOUND_REF="\$\{TOMOFOUND_REF:-([^}]*)\}"[ \t]*$', re.MULTILINE)
_REF_ANY = re.compile(r"^[ \t]*TOMOFOUND_REF=", re.MULTILINE)
_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_SHA = re.compile(r"[0-9a-fA-F]{40}")
# Absolute or home-relative paths and traversal. "${CLAUDE_PLUGIN_ROOT}" is
# removed before matching, so only machine-specific text is left to find.
_HARDCODED_PATH = re.compile(
    r"(?:^|[\s\"'=:])(?:/(?:Users|home|tmp|opt|usr|var|etc|private)/|~/|[A-Za-z]:[\\/])"
    r"|\$\{?HOME\}?|\.\./"
)


# --- Helpers ----------------------------------------------------------------

def load_json(path):
    """Strict UTF-8 JSON load. A BOM or trailing comma raises."""
    raw = path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), f"{path.name} has a BOM"
    return json.loads(raw.decode("utf-8"))


def parse_setup_ref(setup_text):
    """The default TOMOFOUND_REF in setup.sh text. Raises ValueError unless there
    is exactly one assignment of the expected default-value form."""
    if len(_REF_ANY.findall(setup_text)) != 1:
        raise ValueError("expected exactly one TOMOFOUND_REF= assignment")
    matches = _REF_ASSIGNMENT.findall(setup_text)
    if len(matches) != 1:
        raise ValueError('TOMOFOUND_REF is not of the form TOMOFOUND_REF="${TOMOFOUND_REF:-<tag>}"')
    return matches[0]


def check_versions(setup_ref, plugin_version, marketplace_ref):
    """Raise ValueError unless the three release pins describe the same version."""
    if not isinstance(plugin_version, str) or not _SEMVER.fullmatch(plugin_version):
        raise ValueError(f"plugin.json version is not bare semver: {plugin_version!r}")
    expected = "v" + plugin_version
    if setup_ref != expected:
        raise ValueError(f"setup.sh TOMOFOUND_REF {setup_ref!r} != {expected!r}")
    if marketplace_ref != expected:
        raise ValueError(f"marketplace ref {marketplace_ref!r} != {expected!r}")


def check_marketplace_source(source):
    """Raise ValueError unless source is a github object pinned to a release tag."""
    if not isinstance(source, dict):
        # ValueError on purpose: every rejection here is one error type to the caller.
        raise ValueError(f"source must be an object, not a relative path: {source!r}")  # noqa: TRY004
    if source.get("source") != "github":
        raise ValueError(f"source.source must be 'github': {source.get('source')!r}")
    if source.get("repo") != "rotoyang/tomofound":
        raise ValueError(f"unexpected repo: {source.get('repo')!r}")
    ref = source.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("source.ref is missing or empty")
    if ref in {"main", "master", "HEAD"} or _SHA.fullmatch(ref):
        raise ValueError(f"source.ref must be a release tag, not {ref!r}")
    if ref.startswith((".", "/")):
        raise ValueError(f"source.ref looks like a path: {ref!r}")
    if not re.fullmatch(r"v\d+\.\d+\.\d+.*", ref):
        raise ValueError(f"source.ref is not a vX.Y.Z tag: {ref!r}")


def walk_strings(node):
    """Yield every string value (not key) in a parsed JSON document."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk_strings(value)


def hardcoded_path_violations(doc):
    """Strings in doc that contain a machine-specific path. ${CLAUDE_PLUGIN_ROOT}
    itself is allowed."""
    return [s for s in walk_strings(doc) if _HARDCODED_PATH.search(s.replace(ROOT_VAR, ""))]


# --- Version consistency ----------------------------------------------------

def test_three_version_pins_agree():
    setup_ref = parse_setup_ref(SETUP_SH.read_text(encoding="utf-8"))
    plugin_version = load_json(PLUGIN_JSON)["version"]
    marketplace_ref = load_json(MARKETPLACE_JSON)["plugins"][0]["source"]["ref"]
    check_versions(setup_ref, plugin_version, marketplace_ref)
    assert setup_ref == marketplace_ref == "v" + plugin_version


def test_parse_setup_ref_ignores_comments_and_messages():
    text = (
        "#     TOMOFOUND_REF=main bash setup.sh\n"
        'TOMOFOUND_REF="${TOMOFOUND_REF:-v1.2.3}"\n'
        '  echo "   deliberately:  TOMOFOUND_REF=main bash setup.sh"\n'
    )
    assert parse_setup_ref(text) == "v1.2.3"


@pytest.mark.parametrize("text", [
    "echo hi\n",
    'TOMOFOUND_REF="${TOMOFOUND_REF:-v1.0.0}"\nTOMOFOUND_REF="${TOMOFOUND_REF:-v1.0.1}"\n',
    "TOMOFOUND_REF=v1.0.0\n",
])
def test_parse_setup_ref_rejects_missing_duplicate_or_odd_form(text):
    with pytest.raises(ValueError):
        parse_setup_ref(text)


def test_check_versions_accepts_matching_and_prerelease():
    check_versions("v0.5.0", "0.5.0", "v0.5.0")
    check_versions("v1.0.0-rc.1", "1.0.0-rc.1", "v1.0.0-rc.1")


@pytest.mark.parametrize("setup_ref, plugin_version, marketplace_ref", [
    ("v0.5.1", "0.5.0", "v0.5.0"),    # setup.sh drifted
    ("v0.5.0", "0.5.1", "v0.5.0"),    # plugin.json drifted
    ("v0.5.0", "0.5.0", "v0.5.1"),    # marketplace drifted
    ("vv0.5.0", "v0.5.0", "vv0.5.0"),  # doubled v, plugin.json must be bare
    ("v0.5.0", "v0.5.0", "v0.5.0"),   # plugin.json carries a leading v
    ("v0.5.0", "", "v0.5.0"),
    ("v0.5.0", "  ", "v0.5.0"),
    ("v0.5.0", None, "v0.5.0"),
    ("v0.5.0", "0.5.0", "main"),
])
def test_check_versions_rejects_drift(setup_ref, plugin_version, marketplace_ref):
    with pytest.raises(ValueError):
        check_versions(setup_ref, plugin_version, marketplace_ref)


# --- Marketplace --------------------------------------------------------------

def test_marketplace_shape_and_source():
    doc = load_json(MARKETPLACE_JSON)
    assert doc["name"] == "tomofound"
    assert doc["owner"] == {"name": "rotoyang"}
    assert "$schema" not in doc
    assert len(doc["plugins"]) == 1
    entry = doc["plugins"][0]
    assert entry["name"] == "tomofound"
    # plugin.json is the single place the version lives.
    assert "version" not in entry
    assert "$schema" not in entry
    assert entry["source"]["source"] == "github"
    check_marketplace_source(entry["source"])


GOOD_SOURCE = {"source": "github", "repo": "rotoyang/tomofound", "ref": "v0.5.0"}


def test_check_marketplace_source_accepts_good_source():
    check_marketplace_source(GOOD_SOURCE)


@pytest.mark.parametrize("source", [
    "./",
    "./plugin",
    "../elsewhere",
    {**GOOD_SOURCE, "ref": "main"},
    {**GOOD_SOURCE, "ref": "master"},
    {**GOOD_SOURCE, "ref": "HEAD"},
    {**GOOD_SOURCE, "ref": ""},
    {**GOOD_SOURCE, "ref": "   "},
    {**GOOD_SOURCE, "ref": "a" * 40},
    {**GOOD_SOURCE, "ref": "./"},
    {**GOOD_SOURCE, "ref": "0.5.0"},
    {k: v for k, v in GOOD_SOURCE.items() if k != "ref"},
    {**GOOD_SOURCE, "source": "url"},
    {**GOOD_SOURCE, "repo": "someone-else/tomofound"},
])
def test_check_marketplace_source_rejects_unpinned_or_relative(source):
    with pytest.raises(ValueError):
        check_marketplace_source(source)


# --- plugin.json ------------------------------------------------------------

def test_plugin_json_fields():
    doc = load_json(PLUGIN_JSON)
    assert doc["name"] == "tomofound"
    assert doc["description"].strip()
    assert doc["license"] == "MIT"
    assert doc["repository"] == "https://github.com/rotoyang/tomofound"
    # Auto-detected components must not be declared again (duplicate-load error),
    # and there is no user-facing configuration.
    for key in ("hooks", "mcpServers", "skills", "userConfig"):
        assert key not in doc


_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


def check_network_hosts(hosts):
    """Raise ValueError unless hosts is a non-empty list of unique bare hostnames
    (no scheme, port, path, wildcard or whitespace)."""
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("network.hosts must be a non-empty list")
    for host in hosts:
        if not isinstance(host, str) or not _HOSTNAME.fullmatch(host):
            raise ValueError(f"not a bare hostname: {host!r}")
    if len(set(hosts)) != len(hosts):
        raise ValueError("duplicate host")


def test_plugin_declares_author_and_marketplace_description():
    assert load_json(PLUGIN_JSON)["author"] == {"name": "rotoyang"}
    assert load_json(MARKETPLACE_JSON)["description"].strip()


def test_plugin_network_hosts_are_bare_hostnames():
    check_network_hosts(load_json(PLUGIN_JSON)["network"]["hosts"])


def test_plugin_network_hosts_cover_known_server_endpoints():
    # Every host the server code (trivy_server.py, atr_catalog.py) and the README
    # outbound table name. Dropping one would make the declared allowlist too
    # narrow for a feature that is documented to work.
    hosts = set(load_json(PLUGIN_JSON)["network"]["hosts"])
    assert {"github.com", "api.github.com", "raw.githubusercontent.com", "api.osv.dev", "pypi.org"} <= hosts


@pytest.mark.parametrize("hosts", [
    None,
    [],
    "github.com",
    ["https://github.com"],
    ["github.com/aquasecurity"],
    ["github.com:443"],
    ["*.github.com"],
    ["github.com", "github.com"],
    ["localhost"],
    [""],
    [" github.com"],
    [123],
])
def test_check_network_hosts_rejects_non_hostnames(hosts):
    with pytest.raises(ValueError):
        check_network_hosts(hosts)


def test_plugin_license_matches_license_file():
    assert REPO_ROOT.joinpath("LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    assert load_json(PLUGIN_JSON)["license"] == "MIT"


# --- .mcp.json and hooks/hooks.json -------------------------------------------

def test_mcp_json_launches_server_through_plugin_root():
    doc = load_json(MCP_JSON)
    assert list(doc) == ["mcpServers"]
    assert list(doc["mcpServers"]) == ["tomofound"]
    server = doc["mcpServers"]["tomofound"]
    assert server["command"] == "python3"
    assert server["args"] == [SERVER_ARG]


def test_hooks_json_runs_ensure_tools_on_session_start():
    doc = load_json(HOOKS_JSON)
    groups = doc["hooks"]["SessionStart"]
    assert groups
    hooks = [h for group in groups for h in group["hooks"]]
    assert len(hooks) == 1
    hook = hooks[0]
    assert hook["type"] == "command"
    assert hook["async"] is True
    # Seconds, not milliseconds; bool is an int subclass, so check the type too.
    assert type(hook["timeout"]) is int and hook["timeout"] == 600
    assert hook["command"] == f'python3 "{SERVER_ARG}" --ensure-tools'


@pytest.mark.parametrize("path", [MCP_JSON, HOOKS_JSON, PLUGIN_JSON], ids=lambda p: p.name)
def test_launch_config_has_no_hardcoded_paths(path):
    assert hardcoded_path_violations(load_json(path)) == []


@pytest.mark.parametrize("path", [MCP_JSON, HOOKS_JSON], ids=lambda p: p.name)
def test_launch_config_uses_plugin_root(path):
    assert any(ROOT_VAR in s for s in walk_strings(load_json(path)))


def test_plugin_root_targets_exist():
    for doc in (load_json(MCP_JSON), load_json(HOOKS_JSON)):
        for s in walk_strings(doc):
            for match in re.finditer(r'\$\{CLAUDE_PLUGIN_ROOT\}(/[^"\s]+)', s):
                assert (REPO_ROOT / match.group(1).lstrip("/")).is_file(), match.group(0)
    assert (REPO_ROOT / "skills" / "security-scan" / "SKILL.md").is_file()


@pytest.mark.parametrize("value", [
    "/Users/alice/tomofound/server/trivy_server.py",
    "/home/alice/tomofound/server/trivy_server.py",
    "python3 /opt/tomofound/server/trivy_server.py",
    'python3 "/tmp/x/trivy_server.py" --ensure-tools',
    "~/.tomofound/server/trivy_server.py",
    "$HOME/.tomofound/server/trivy_server.py",
    "${HOME}/.tomofound/server/trivy_server.py",
    "C:\\Users\\alice\\server.py",
    "D:/tomofound/server.py",
    f"{ROOT_VAR}/../other/server.py",
])
def test_hardcoded_path_detector_catches_machine_paths(value):
    assert hardcoded_path_violations({"args": [value]}) == [value]


def test_hardcoded_path_detector_allows_plugin_root():
    assert hardcoded_path_violations(
        {"command": f'python3 "{SERVER_ARG}" --ensure-tools', "args": [SERVER_ARG]}
    ) == []
