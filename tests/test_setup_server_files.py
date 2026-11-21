"""Keeps setup.sh's SERVER_FILES list in step with trivy_server.py's runtime
imports. A server module that trivy_server.py imports but SERVER_FILES omits
makes `curl ... setup.sh | bash` install a server that fails at import time.

Everything here is text-based: setup.sh is parsed, never executed, and nothing
touches the network."""

import ast
import re
import shlex
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = REPO_ROOT / "server"
SETUP_SH = REPO_ROOT / "setup.sh"
ENTRYPOINT = SERVER_DIR / "trivy_server.py"

# Anchored to the start of a line so that "${SERVER_FILES[@]}" and comments
# such as "# SERVER_FILES=(...)" do not match.
_ASSIGNMENT = re.compile(r"^[ \t]*SERVER_FILES=\(", re.MULTILINE)
# Plain filenames only. Anything with $, globs or command substitution would
# expand at install time in a way this test cannot see.
_LITERAL_NAME = re.compile(r"[A-Za-z0-9_.-]+")


# --- Helpers ----------------------------------------------------------------

def local_imports(source_text, server_dir):
    """Return the '<name>.py' filenames of server_dir modules that source_text
    imports.

    Walks the whole tree so imports inside functions count. Names that do not
    map to an existing server_dir/<name>.py (stdlib, mcp, ...) are dropped.

    shortcut: static ast only. importlib.import_module() or __import__() with a
    computed name is invisible here. Upgrade if trivy_server.py starts loading
    server modules dynamically."""
    names = set()
    for node in ast.walk(ast.parse(source_text)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.module:
                    # from .foo import bar
                    names.add(node.module.split(".")[0])
                else:
                    # from . import foo: module is None, the modules are in names
                    names.update(a.name for a in node.names if a.name != "*")
            elif node.module == "server":
                # from server import foo
                names.update(a.name for a in node.names if a.name != "*")
            elif node.module:
                parts = node.module.split(".")
                # from server.foo import bar, else from foo.sub import bar
                names.add(parts[1] if parts[0] == "server" and len(parts) > 1 else parts[0])
    return {f"{name}.py" for name in names if (server_dir / f"{name}.py").is_file()}


def local_module_closure(entry_path, server_dir):
    """Return the filenames of every server_dir module reachable from entry_path
    through local imports. The entry module is included only if something in
    the chain imports it back."""
    found = set()
    pending = [entry_path]
    while pending:
        source = pending.pop().read_text(encoding="utf-8")
        for filename in local_imports(source, server_dir):
            if filename not in found:
                found.add(filename)
                pending.append(server_dir / filename)
    return found


def parse_server_files(setup_text):
    """Return the entries of the SERVER_FILES=( ... ) array in setup.sh text.

    Raises ValueError if the array is absent, assigned twice, unterminated,
    empty, or contains an element that is not a plain filename. Comments and
    quoting are handled by shlex in POSIX mode, which matches bash for a list
    of filenames."""
    matches = list(_ASSIGNMENT.finditer(setup_text))
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one SERVER_FILES=( assignment, found {len(matches)}"
        )
    lexer = shlex.shlex(setup_text[matches[0].end():], posix=True)
    # Split on whitespace only, so "foo.py)" arrives as one token and the
    # closing paren is detected by its suffix. Comments default to "#".
    lexer.whitespace_split = True

    entries = []
    closed = False
    for token in lexer:
        closes = token.endswith(")")
        name = token[:-1] if closes else token
        if name:
            if not _LITERAL_NAME.fullmatch(name):
                raise ValueError(f"SERVER_FILES element is not a plain filename: {name!r}")
            entries.append(name)
        if closes:
            closed = True
            break
    if not closed:
        raise ValueError("SERVER_FILES=( is never closed")
    if not entries:
        raise ValueError("SERVER_FILES=() is empty")
    return entries


def missing_server_files(entry_path, server_dir, setup_text):
    """Sorted names of modules needed by entry_path (plus the entry itself)
    that setup_text's SERVER_FILES does not list."""
    expected = local_module_closure(entry_path, server_dir) | {entry_path.name}
    actual = set(parse_server_files(setup_text))
    return sorted(expected - actual)


def assert_server_files_complete(entry_path, server_dir, setup_text):
    missing = missing_server_files(entry_path, server_dir, setup_text)
    assert not missing, (
        "setup.sh SERVER_FILES does not list modules that trivy_server.py needs at "
        f"runtime; curl | bash installs would break. Missing: {missing}"
    )


# --- Detector: AST import forms ---------------------------------------------

def test_local_imports_recognise_each_import_form(tmp_path):
    for name in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]:
        (tmp_path / f"{name}.py").write_text("", encoding="utf-8")
    source = textwrap.dedent("""\
        import os
        import mcp
        import alpha
        import beta as b
        from gamma import thing
        from delta.sub import x
        from server.epsilon import y
        from server import zeta
        from . import eta
        from .beta import c
        from alpha import *
        def f():
            import theta
    """)
    assert local_imports(source, tmp_path) == {
        "alpha.py", "beta.py", "gamma.py", "delta.py", "epsilon.py",
        "zeta.py", "eta.py", "theta.py",
    }


def test_local_module_closure_follows_transitive_imports(tmp_path):
    (tmp_path / "entry.py").write_text("import middle\n", encoding="utf-8")
    (tmp_path / "middle.py").write_text("from leaf import thing\n", encoding="utf-8")
    (tmp_path / "leaf.py").write_text("import json\n", encoding="utf-8")
    assert local_module_closure(tmp_path / "entry.py", tmp_path) == {"middle.py", "leaf.py"}

    # If setup.sh lists the entry and its direct import but not the transitive
    # one, the check must name the transitive module.
    setup_text = "SERVER_FILES=(\n  entry.py\n  middle.py\n)\n"
    assert missing_server_files(tmp_path / "entry.py", tmp_path, setup_text) == ["leaf.py"]


# --- Real repository ----------------------------------------------------------

def test_setup_sh_server_files_covers_trivy_server_imports():
    setup_text = SETUP_SH.read_text(encoding="utf-8")
    expected = local_module_closure(ENTRYPOINT, SERVER_DIR)
    # Sanity check: the detector really sees the modules trivy_server.py imports
    # today, so an empty result cannot pass silently.
    assert {"python_analyzer.py", "atr_catalog.py"} <= expected
    assert_server_files_complete(ENTRYPOINT, SERVER_DIR, setup_text)


# --- Negative case with fake data -------------------------------------------

def test_missing_module_in_server_files_fails(tmp_path):
    (tmp_path / "trivy_server.py").write_text(
        "import atr_catalog\nfrom python_analyzer import analyze_python\n",
        encoding="utf-8",
    )
    (tmp_path / "atr_catalog.py").write_text("", encoding="utf-8")
    (tmp_path / "python_analyzer.py").write_text("", encoding="utf-8")
    entry = tmp_path / "trivy_server.py"

    incomplete = "SERVER_FILES=(\n  trivy_server.py\n  python_analyzer.py\n)\n"
    with pytest.raises(AssertionError, match="atr_catalog.py"):
        assert_server_files_complete(entry, tmp_path, incomplete)

    complete = "SERVER_FILES=(\n  trivy_server.py\n  python_analyzer.py\n  atr_catalog.py\n)\n"
    assert_server_files_complete(entry, tmp_path, complete)


# --- Parsing the SERVER_FILES array -----------------------------------------

def test_parse_single_line_array():
    assert parse_server_files("SERVER_FILES=(a.py b.py)\n") == ["a.py", "b.py"]


def test_parse_multiline_with_comments_and_quotes():
    text = (
        "SERVER_FILES=(\n"
        "  trivy_server.py   # the entry point (runs first)\n"
        '  "python_analyzer.py"\n'
        "  'atr_catalog.py'\n"
        ")\n"
    )
    assert parse_server_files(text) == [
        "trivy_server.py", "python_analyzer.py", "atr_catalog.py",
    ]


@pytest.mark.parametrize("text, message", [
    ("echo hi\n", "found 0"),
    ("SERVER_FILES=(a.py)\nSERVER_FILES=(b.py)\n", "found 2"),
    ('for f in "${SERVER_FILES[@]}"; do\n# SERVER_FILES=(x.py)\n', "found 0"),
    ("SERVER_FILES=()\n", "empty"),
    ("SERVER_FILES=(\n  a.py\n", "never closed"),
    ('SERVER_FILES=(\n  "a.py\n)\n', "quotation"),
    ("SERVER_FILES=(\n  $HOME.py\n)\n", "plain filename"),
])
def test_malformed_server_files_raises(text, message):
    with pytest.raises(ValueError, match=message):
        parse_server_files(text)
