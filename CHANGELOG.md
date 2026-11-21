# Changelog

## Unreleased

### Added
- 新增 `server/trivy_server.py` 的 `--ensure-tools` 命令列旗標，支援由 Claude Code plugin 的 `SessionStart` hook 於背景安全呼叫：
  - **純標準函式庫離線快路徑**：在 `_bootstrap()` 執行前僅以標準函式庫檢查 venv 依賴版本（`.tomofound-deps == _DEPS_VERSION` 且 `venv` Python 存在）、ATR 規則目錄版本（`meta.json` 與 `atr_catalog.ATR_PIN` 一致）及 Trivy 是否可用（`PATH` 上存在或 `~/.tomofound/tools/trivy` 存在）；三者皆成立時立即以退出碼 `0` 結束，不連網、不觸碰鎖檔亦不 re-exec。
  - **受鎖保護的補齊慢路徑**：任一條件未滿足時，先透過 `_bootstrap()` 建立或更新 venv，再於 `_ensure_tools_cli()` 中取得 `~/.tomofound/tools.lock` 跨程序檔案鎖、持鎖後重新檢查狀態，僅補齊缺少的工具（跳過已是最新版本的 ATR 目錄）；所有輸出皆導向 `stderr`，避免污染 MCP 的 JSON-RPC `stdout`。
- 新增跨程序檔案鎖 `_file_lock()`（POSIX 使用 `fcntl.flock`，Windows 使用 `msvcrt.locking` 搭配 `LK_NBLCK` 重試迴圈與 `seek(0)` 對齊；鎖檔置於 `~/.tomofound/` 底下且不刪除）。

### Changed
- 為 `server/trivy_server.py` 的 `_bootstrap()` 建立 venv 與 `pip install` 區段加上 `~/.tomofound/venv.lock` 跨程序檔案鎖與鎖內雙重檢查（`_venv_ready()`），並在 re-exec 前釋放鎖，同時將 `venv`／`pip` 子程序輸出導向 `sys.stderr`，防止 MCP server 啟動與背景 hook 併發建置 venv 導致損毀。
- `_install_tools_cli()` 新增 `skip_current_atr: bool = False` 參數，使 `--ensure-tools` 可跳過已為最新版本的 ATR 目錄下載，並保留 `--install-tools` 既有的強制重抓行為。
