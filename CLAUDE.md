# Project conventions

## Supply-chain documentation must stay in sync

tomofound is a security tool whose users run it with elevated trust. Its own external dependencies and outbound network surface are documented in the **Supply chain** section of `README.md`. **Whenever a change introduces, removes, or updates any of the following, the README tables MUST be updated in the same PR:**

- The `_MCP_PIN` constant in `server/trivy_server.py` (or any new `pip install` the bootstrap performs).
- A new external binary fetched at install or first-run time (currently only Trivy).
- A new outbound URL pattern called from server code (`urllib.request.urlopen`, `subprocess.run(["git", ...])`, the `_SSRF_SAFE_OPENER`, etc.).
- A new file the installer writes outside `~/.tomofound/`.
- A new bundled repo asset that ships to user machines (`server/`, `skills/`, `integrations/`, `setup.sh`).
- A new Python module under `server/` that `trivy_server.py` imports at runtime. **The `SERVER_FILES` list inside `setup.sh` MUST be updated in the same PR** — otherwise real users running `curl … setup.sh | bash` get a broken install (the import succeeds at dev time on a full git tree, but `setup.sh` only fetches the files it explicitly lists). Smoke-test by re-running `bash setup.sh` against a clean `~/.tomofound/`.

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

Tests for `server/trivy_server.py` and `server/python_analyzer.py` live under `tests/`. New MCP tools or analyzer rules need matching test coverage in the same PR; refactors that don't change behaviour shouldn't need new tests but must keep the full suite passing (`python -m pytest tests/`).

## Releases pin the installer, and the order matters

`setup.sh` fetches the server and skill from `TOMOFOUND_REF`, which defaults to a
release tag rather than `main`. That is deliberate: tomofound pins Trivy, the ATR
catalog and the mcp SDK, and serving its own source off a moving branch while
making that argument about everyone else's does not hold up. A commit merged to
`main` must not reach `curl | bash` installs until a release says so.

Cutting a release, in this order:

1. In the release PR, set `TOMOFOUND_REF` in `setup.sh` to the version being cut.
2. Merge it.
3. Tag **that** commit and publish.

Reversing 2 and 3 leaves `main` pointing at a tag that does not exist yet, and
the documented installer fails for everyone who runs it in that window. The
failure is loud and explains itself — it does not silently fall back to `main`,
because that would reintroduce exactly the exposure the pin removes — but it is
still a broken install command on the front page of the README.

Before publishing, confirm the pinned URLs actually resolve. A tag that exists in
git is not the same as one `raw.githubusercontent.com` will serve:

```bash
for f in server/trivy_server.py server/python_analyzer.py server/atr_catalog.py \
         skills/security-scan/security-scan.md \
         integrations/codex/skills/security-scan/SKILL.md \
         integrations/gemini/skills/security-scan/SKILL.md; do
  curl -sS -o /dev/null -w "%{http_code}  $f\n" \
    "https://raw.githubusercontent.com/rotoyang/tomofound/<tag>/$f"
done
```

All six must return 200. `setup.ps1` carries its own `$BaseUrl` and needs the
same bump whenever it is in play.
