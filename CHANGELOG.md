# Changelog

## [Unreleased]

### Added
- Added `tests/test_setup_server_files.py`, which statically checks that the `SERVER_FILES` array in `setup.sh` lists `server/trivy_server.py` and every local `server/` module it imports, directly or transitively (without running `setup.sh` or touching the network). It covers the different Python import forms, a negative case for a missing module, and malformed array formats, so a `curl ... setup.sh | bash` install cannot ship with a missing file.

### Changed
- Renamed `skills/security-scan/security-scan.md` to `skills/security-scan/SKILL.md` (contents unchanged) to follow the Claude Code plugin standard filename.
- Updated `_PROMPT_SOURCE_CANDIDATES` in `server/trivy_server.py` to check `SKILL.md` in the repository and `DATA_ROOT` before falling back to legacy `security-scan.md` paths for backward compatibility with older installations.
- Updated `setup.sh` to fetch `skills/security-scan/SKILL.md` via a temporary file with fallback to `skills/security-scan/security-scan.md` (supporting older pinned refs such as `v0.5.0`), installing `SKILL.md` alongside an identical `security-scan.md` compatibility copy for the `v0.5.0` server.
- Updated skill path references in `README.md` and `CLAUDE.md`, updated existing test paths, and added unit tests in `tests/test_trivy_server.py` covering prompt source candidate ordering and fallback behavior.
