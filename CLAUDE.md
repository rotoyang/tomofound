# Project conventions

## Supply-chain documentation must stay in sync

tomofound is a security tool whose users run it with elevated trust. Its own external dependencies and outbound network surface are documented in the **Supply chain** section of `README.md`. **Whenever a change introduces, removes, or updates any of the following, the README tables MUST be updated in the same PR:**

- The `_MCP_PIN` constant in `server/trivy_server.py` (or any new `pip install` the bootstrap performs).
- A new external binary fetched at install or first-run time (currently only Trivy).
- A new outbound URL pattern called from server code (`urllib.request.urlopen`, `subprocess.run(["git", ...])`, the `_SSRF_SAFE_OPENER`, etc.).
- A new file the installer writes outside `~/.tomofound/`.
- A new bundled repo asset that ships to user machines (`server/`, `skills/`, `integrations/`, `setup.sh`).

If you can't update the README tables in the same change (for example because the new dependency isn't decided yet), open the PR as a draft and list the missing entries in the PR description.

## Tests track behaviour, not paths

Tests for `server/trivy_server.py` and `server/python_analyzer.py` live under `tests/`. New MCP tools or analyzer rules need matching test coverage in the same PR; refactors that don't change behaviour shouldn't need new tests but must keep the existing 127 passing.
