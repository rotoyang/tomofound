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
CLAUDE_CONFIG_PATH="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
CODEX_CONFIG_PATH="$HOME/.codex/config.toml"
CODEX_SKILL_DIR="$HOME/.codex/skills/security-scan"

INSTALL_CLAUDE=1
INSTALL_CODEX=1

usage() {
  cat <<'EOF'
Usage: ./setup.sh [--all|--claude|--codex]

  --all      Install shared tomofound assets and configure both Claude and Codex (default)
  --claude   Configure Claude only
  --codex    Configure Codex only
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      INSTALL_CLAUDE=1
      INSTALL_CODEX=1
      ;;
    --claude)
      INSTALL_CLAUDE=1
      INSTALL_CODEX=0
      ;;
    --codex)
      INSTALL_CLAUDE=0
      INSTALL_CODEX=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

echo "Setting up tomofound..."

mkdir -p "$SERVER_DIR" "$SKILL_DIR"
curl -fsSL "$BASE_URL/server/trivy_server.py" -o "$SERVER_DIR/trivy_server.py"
chmod +x "$SERVER_DIR/trivy_server.py"
curl -fsSL "$BASE_URL/skills/security-scan/security-scan.md" -o "$SKILL_DIR/security-scan.md"
echo "✅ Server + prompt source installed to $DATA_ROOT"

if [[ "$INSTALL_CLAUDE" -eq 1 ]]; then
mkdir -p "$(dirname "$CLAUDE_CONFIG_PATH")"
SERVER_PATH="$SERVER_DIR/trivy_server.py" CONFIG_PATH="$CLAUDE_CONFIG_PATH" python3 - <<'PYEOF'
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
fi

if [[ "$INSTALL_CODEX" -eq 1 ]]; then
mkdir -p "$CODEX_SKILL_DIR" "$(dirname "$CODEX_CONFIG_PATH")"
curl -fsSL "$BASE_URL/integrations/codex/skills/security-scan/SKILL.md" -o "$CODEX_SKILL_DIR/SKILL.md"
echo "✅ Codex skill installed to $CODEX_SKILL_DIR"

SERVER_PATH="$SERVER_DIR/trivy_server.py" CONFIG_PATH="$CODEX_CONFIG_PATH" python3 - <<'PYEOF'
import os, re

config_path = os.environ["CONFIG_PATH"]
server_path = os.environ["SERVER_PATH"]
block = (
    "[mcp_servers.tomofound]\n"
    f'args = ["{server_path}"]\n'
    'command = "python3"\n'
    "startup_timeout_sec = 120\n"
)

if os.path.exists(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        text = f.read()
else:
    text = ""

pattern = re.compile(r"(?ms)^\[mcp_servers\.tomofound\]\n.*?(?=^\[|\Z)")
if pattern.search(text):
    new_text = pattern.sub(block, text).rstrip() + "\n"
else:
    sep = "\n\n" if text.strip() else ""
    new_text = text.rstrip() + sep + block

if new_text == text:
    print("ℹ️  Codex MCP server already registered (no change)")
else:
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(new_text)
    print(f"✅ Codex MCP server registered in {config_path}")
PYEOF
fi

echo ""
echo "─────────────────────────────────────────────"
echo "Installation complete. Next steps:"
echo ""
if [[ "$INSTALL_CLAUDE" -eq 1 ]]; then
echo "  • Quit Claude fully (Cmd-Q) and reopen it."
echo "    Type \"/\" in any chat — you should see /security_scan."
fi
if [[ "$INSTALL_CODEX" -eq 1 ]]; then
echo "  • Restart Codex or open a new Codex thread."
echo "    Invoke the security-scan skill when auditing extensions."
fi
echo "─────────────────────────────────────────────"
