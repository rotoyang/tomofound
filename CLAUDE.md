# Project conventions

## Supply-chain documentation must stay in sync

tomofound is a security tool whose users run it with elevated trust. Its own external dependencies and outbound network surface are documented in the **Supply chain** section of `README.md`. **Whenever a change introduces, removes, or updates any of the following, the README tables MUST be updated in the same PR:**

- The `_MCP_PIN` constant in `server/trivy_server.py` (or any new `pip install` the bootstrap performs).
- A new external binary fetched at install or first-run time (currently only Trivy).
- A new outbound URL pattern called from server code (`urllib.request.urlopen`, `subprocess.run(["git", ...])`, the `_SSRF_SAFE_OPENER`, etc.).
- A new file the installer writes outside `~/.tomofound/`.
- A new bundled repo asset that ships to user machines (`server/`, `skills/`, `integrations/`, `setup.sh`).

If you can't update the README tables in the same change (for example because the new dependency isn't decided yet), open the PR as a draft and list the missing entries in the PR description.

## License verification is mandatory before integrating any new dependency

Before opening a PR that adds a new runtime dependency, external binary, fetched data source, or threat-intel catalog, the contributor MUST:

1. Locate the upstream LICENSE file at the exact commit / tag / version being pinned. Record the SPDX identifier and the URL to the LICENSE file.
2. Confirm the license actually covers the artifact we are consuming — some projects split engine code and rule data under different licenses; the license that matters is the one on what we read.
3. Confirm our usage model is compatible. For v1, tomofound fetches and matches but does not redistribute upstream catalogs (downloads happen on the user's machine, on the user's behalf, under upstream's own terms). Adding a vendored snapshot to the repo is redistribution and requires a permissive license + LICENSE retention.
4. Record the result in the README **Supply chain > Runtime dependencies** table (with a License column linking to the upstream LICENSE) AND in the README **Supply chain > Attribution** section.
5. Reject GPL / AGPL / "no LICENSE file" / share-alike data licenses for v1 unless you can document why an exception is required and how it doesn't expose tomofound's own license (Apache-2.0) to virality.

`docs/catalog-architecture.md` contains the full protocol (local design notes, gitignored). The Supply chain table in `README.md` is the user-facing artifact that must be kept current.

## Tests track behaviour, not paths

Tests for `server/trivy_server.py` and `server/python_analyzer.py` live under `tests/`. New MCP tools or analyzer rules need matching test coverage in the same PR; refactors that don't change behaviour shouldn't need new tests but must keep the existing 127 passing.
