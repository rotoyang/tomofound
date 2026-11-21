# Changelog

## [Unreleased]

### Added
- 新增 `tests/test_setup_server_files.py`，透過靜態分析檢查 `setup.sh` 的 `SERVER_FILES` 陣列是否涵蓋 `server/trivy_server.py` 本身及其所有直接與遞移匯入的本地 `server/` 模組（不執行 `setup.sh`、不連網），並涵蓋各式 Python 匯入語法、漏列模組負向測試與異常陣列格式驗證，避免 `curl ... setup.sh | bash` 安裝到缺檔版本。
