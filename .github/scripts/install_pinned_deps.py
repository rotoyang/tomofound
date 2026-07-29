#!/usr/bin/env python3
"""Install the runtime deps that `_bootstrap()` pins, read from the source of truth.

CI used to `pip install mcp` unpinned while real installs get an exact pin from
`_PIP_DEPS`. That gap is not academic: the mcp SDK 2.0.0 release replaced the
low-level `Server` decorators with constructor `on_*` params, so an unpinned CI
would have been testing an SDK no user runs — and `trivy_server.py` raises
AttributeError at import under it, which the module's `except ImportError`
fallback does not catch.

Parsing `_PIP_DEPS` instead of restating it here means CI and users can never
drift: a bump to the constant is picked up on the next run, and a rename that
loses the constant fails loudly rather than silently installing whatever PyPI
serves today.
"""

import ast
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER_SOURCE = REPO_ROOT / "server" / "trivy_server.py"


def pinned_deps() -> list[str]:
    """Return the `_PIP_DEPS` list literal without importing the server module."""
    tree = ast.parse(SERVER_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(target, "id", None) == "_PIP_DEPS" for target in node.targets
        ):
            deps = ast.literal_eval(node.value)
            if not deps or not all(isinstance(d, str) for d in deps):
                raise SystemExit(f"_PIP_DEPS in {SERVER_SOURCE} is not a list of strings")
            return list(deps)
    raise SystemExit(f"_PIP_DEPS not found in {SERVER_SOURCE}")


def main() -> int:
    deps = pinned_deps()
    print(f"Installing runtime deps pinned in {SERVER_SOURCE.relative_to(REPO_ROOT)}:")
    for dep in deps:
        print(f"  {dep}")
    subprocess.run([sys.executable, "-m", "pip", "install", *deps], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
