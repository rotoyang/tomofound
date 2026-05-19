#!/bin/bash
set -e

BASE_URL="https://raw.githubusercontent.com/rotoyang/tomofound/main"
DEST="$HOME/.claude/plugins/data/tomofound/server"

echo "Setting up tomofound security-scan MCP server..."

# 1. Copy server script
mkdir -p "$DEST"
curl -fsSL "$BASE_URL/server/trivy_server.py" -o "$DEST/trivy_server.py"
chmod +x "$DEST/trivy_server.py"
echo "✅ Server script installed to $DEST/trivy_server.py"

# 2. Register MCP server in ~/.claude/settings.json
python3 - <<PYEOF
import json, os

settings_path = os.path.expanduser("~/.claude/settings.json")
with open(settings_path) as f:
    settings = json.load(f)

server_entry = {
    "command": "python3",
    "args": [os.path.expanduser("~/.claude/plugins/data/tomofound/server/trivy_server.py")]
}

mcp = settings.setdefault("mcpServers", {})
if mcp.get("tomofound-trivy") == server_entry:
    print("ℹ️  MCP server already registered (no change)")
else:
    mcp["tomofound-trivy"] = server_entry
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("✅ MCP server registered in ~/.claude/settings.json")
PYEOF

echo ""
echo "─────────────────────────────────────────────"
echo "Installation complete. Next steps:"
echo ""
echo "  1. Restart Claude Code Desktop App"
echo "  2. Download security-scan.md from:"
echo "     https://github.com/rotoyang/tomofound/raw/main/skills/security-scan/security-scan.md"
echo "  3. Drag it into Customize > Skills"
echo "─────────────────────────────────────────────"
