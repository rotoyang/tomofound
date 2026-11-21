# Changelog

## [Unreleased]

### Added
- Added `tests/test_setup_server_files.py`, which statically checks that the `SERVER_FILES` array in `setup.sh` lists `server/trivy_server.py` and every local `server/` module it imports, directly or transitively (without running `setup.sh` or touching the network). It covers the different Python import forms, a negative case for a missing module, and malformed array formats, so a `curl ... setup.sh | bash` install cannot ship with a missing file.
- Added a `--ensure-tools` flag to `server/trivy_server.py`, safe to call in the background from a Claude Code plugin `SessionStart` hook:
  - **Offline fast path, standard library only**: before `_bootstrap()` runs it checks that the venv deps are current (`.tomofound-deps == _DEPS_VERSION` and the venv Python exists), that the ATR catalog matches `atr_catalog.ATR_PIN`, and that Trivy is available (on `PATH` or at `~/.tomofound/tools/trivy`). When all three hold it exits `0` with no network access, no lock and no re-exec.
  - **Locked slow path**: otherwise it builds or updates the venv through `_bootstrap()`, then takes the `~/.tomofound/tools.lock` cross-process lock, re-checks, and installs only what is missing (an up-to-date ATR catalog is not re-downloaded). All output goes to `stderr` so MCP's JSON-RPC `stdout` stays clean.
- Added `_file_lock()`, a cross-process lock (`fcntl.flock` on POSIX; `msvcrt.locking` with an `LK_NBLCK` retry loop and `seek(0)` alignment on Windows). Lock files live in `~/.tomofound/` and are never deleted.

### Changed
- Renamed `skills/security-scan/security-scan.md` to `skills/security-scan/SKILL.md` (contents unchanged) to follow the Claude Code plugin standard filename.
- Updated `_PROMPT_SOURCE_CANDIDATES` in `server/trivy_server.py` to check `SKILL.md` in the repository and `DATA_ROOT` before falling back to legacy `security-scan.md` paths for backward compatibility with older installations.
- Updated `setup.sh` to fetch `skills/security-scan/SKILL.md` via a temporary file with fallback to `skills/security-scan/security-scan.md` (supporting older pinned refs such as `v0.5.0`), installing `SKILL.md` alongside an identical `security-scan.md` compatibility copy for the `v0.5.0` server.
- Updated skill path references in `README.md` and `CLAUDE.md`, updated existing test paths, and added unit tests in `tests/test_trivy_server.py` covering prompt source candidate ordering and fallback behavior.
- `_bootstrap()` in `server/trivy_server.py` now creates the venv and runs `pip install` under a `~/.tomofound/venv.lock` cross-process lock with a re-check inside the lock (`_venv_ready()`), releases the lock before re-exec, and sends `venv`/`pip` output to `sys.stderr`. This keeps an MCP server start and a background hook from corrupting each other's venv build.
- `_install_tools_cli()` takes a new `skip_current_atr: bool = False` parameter so `--ensure-tools` can skip an already-current ATR catalog, while `--install-tools` keeps its existing always-refetch behaviour.
