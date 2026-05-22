#!/bin/bash
set -e

if [[ "$(uname)" != "Darwin" ]]; then
  echo "tomofound currently supports macOS only. Aborting."
  exit 1
fi

BASE_URL="https://raw.githubusercontent.com/rotoyang/tomofound/main"
DATA_ROOT="$HOME/.tomofound"
SERVER_DIR="$DATA_ROOT/server"
SKILL_DIR="$DATA_ROOT/skills/security-scan"
CONFIG_PATH="$HOME/Library/Application Support/Claude/claude_desktop_config.json"

echo "Setting up tomofound..."

mkdir -p "$SERVER_DIR" "$SKILL_DIR"
curl -fsSL "$BASE_URL/server/trivy_server.py" -o "$SERVER_DIR/trivy_server.py"
chmod +x "$SERVER_DIR/trivy_server.py"
curl -fsSL "$BASE_URL/skills/security-scan/security-scan.md" -o "$SKILL_DIR/security-scan.md"
echo "✅ Server + prompt source installed to $DATA_ROOT"

mkdir -p "$(dirname "$CONFIG_PATH")"
SERVER_PATH="$SERVER_DIR/trivy_server.py" CONFIG_PATH="$CONFIG_PATH" python3 - <<'PYEOF'
import json, os

config_path = os.environ["CONFIG_PATH"]
server_path = os.environ["SERVER_PATH"]

if os.path.exists(config_path):
    with open(config_path) as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            config = {}
else:
    config = {}

entry = {"command": "python3", "args": [server_path]}
servers = config.setdefault("mcpServers", {})

if servers.get("tomofound") == entry:
    print("ℹ️  MCP server already registered (no change)")
else:
    servers["tomofound"] = entry
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"✅ MCP server registered in {config_path}")
PYEOF

echo ""
echo "─────────────────────────────────────────────"
echo "Installation complete. Next steps:"
echo ""
echo "  1. Quit Claude Desktop App fully (Cmd-Q) and reopen it."
echo "  2. Type \"/\" in any chat — you should see /tomofound__security_scan."
echo "─────────────────────────────────────────────"
