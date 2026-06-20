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
VENV_DIR="$DATA_ROOT/venv"
CATALOGS_DIR="$DATA_ROOT/catalogs"
TOOLS_DIR="$DATA_ROOT/tools"
REPORTS_DIR="$DATA_ROOT/reports"
CLAUDE_CONFIG_PATH="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
CODEX_CONFIG_PATH="$HOME/.codex/config.toml"
CODEX_SKILL_DIR="$HOME/.codex/skills/security-scan"

INSTALL_CLAUDE=1
INSTALL_CODEX=1
CLEAN_INSTALL=0

usage() {
  cat <<'EOF'
Usage: ./setup.sh [--all|--claude|--codex] [--clean]

  --all      Install shared tomofound assets and configure both Claude and Codex (default)
  --claude   Configure Claude only
  --codex    Configure Codex only
  --clean    Remove all of ~/.tomofound/ (including reports, catalogs, Trivy
             binary) before installing. Confirms with a 5-second abort window.
             Default behaviour preserves these, so --clean is only needed when
             you want a genuinely fresh install.
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
    --clean)
      CLEAN_INSTALL=1
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

# -----------------------------------------------------------------------------
# Pre-flight: detect existing install and tell the user what we'll touch.
# Re-running setup.sh is safe — server files and the skill prompt are atomically
# overwritten, the venv self-refreshes deps via the _DEPS_VERSION marker, and
# catalogs / Trivy binary / historical reports are explicitly preserved.
# -----------------------------------------------------------------------------
if [[ -d "$DATA_ROOT" ]]; then
  echo ""
  echo "📦 Existing install detected at $DATA_ROOT:"
  if [[ -d "$SERVER_DIR" ]]; then
    server_count=$(find "$SERVER_DIR" -maxdepth 1 -name "*.py" 2>/dev/null | wc -l | tr -d ' ')
    echo "   • server/        — $server_count Python module(s) (will be refreshed)"
  fi
  if [[ -d "$SKILL_DIR" ]]; then
    echo "   • skills/        — security-scan prompt (will be refreshed)"
  fi
  if [[ -d "$VENV_DIR" ]]; then
    if [[ -f "$VENV_DIR/.tomofound-deps" ]]; then
      marker=$(cat "$VENV_DIR/.tomofound-deps" 2>/dev/null || echo "?")
      echo "   • venv/          — preserved (deps version $marker; will auto-refresh on next server start if changed)"
    else
      echo "   • venv/          — preserved (legacy install; will auto-install missing deps on next server start)"
    fi
  fi
  if [[ -d "$CATALOGS_DIR" ]]; then
    catalog_count=$(find "$CATALOGS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    echo "   • catalogs/      — $catalog_count cached catalog(s) preserved (run atr_update via Claude to refresh)"
  fi
  if [[ -d "$TOOLS_DIR" ]]; then
    if [[ -x "$TOOLS_DIR/trivy" ]]; then
      echo "   • tools/trivy    — preserved (auto-managed by Trivy itself)"
    else
      echo "   • tools/         — preserved"
    fi
  fi
  if [[ -d "$REPORTS_DIR" ]]; then
    report_count=$(find "$REPORTS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$report_count" -gt 0 ]]; then
      echo "   • reports/       — $report_count historical scan(s) preserved"
    fi
  fi
  echo ""
fi

if [[ "$CLEAN_INSTALL" -eq 1 && -d "$DATA_ROOT" ]]; then
  echo "🗑  --clean: about to delete the entire $DATA_ROOT directory."
  echo "   This wipes reports, cached catalogs, the Trivy binary, and the venv."
  echo "   Press Ctrl-C within 5 seconds to abort."
  for i in 5 4 3 2 1; do
    printf "   %d... " "$i"
    sleep 1
  done
  echo ""
  rm -rf "$DATA_ROOT"
  echo "   Removed."
  echo ""
fi

echo "Setting up tomofound..."

mkdir -p "$SERVER_DIR" "$SKILL_DIR"

# Every Python module trivy_server.py imports at runtime must be listed here.
# When adding a new file under server/, also add it to this list AND to the
# README Supply chain > Repository assets table (enforced by CLAUDE.md).
SERVER_FILES=(
  trivy_server.py
  python_analyzer.py
  atr_catalog.py
)
for f in "${SERVER_FILES[@]}"; do
  curl -fsSL "$BASE_URL/server/$f" -o "$SERVER_DIR/$f"
done
chmod +x "$SERVER_DIR/trivy_server.py"
curl -fsSL "$BASE_URL/skills/security-scan/security-scan.md" -o "$SKILL_DIR/security-scan.md"
echo "✅ Server (${#SERVER_FILES[@]} modules) + prompt source installed to $DATA_ROOT"

# -----------------------------------------------------------------------------
# Post-install reconciliation: warn about orphan .py files in server/ that the
# current version doesn't ship. We don't auto-delete — leftover files are
# harmless, but the user deserves to know what's there.
# -----------------------------------------------------------------------------
orphans=()
expected_set=" ${SERVER_FILES[*]} "
while IFS= read -r f; do
  bn=$(basename "$f")
  case "$expected_set" in
    *" $bn "*) ;;
    *) orphans+=("$bn") ;;
  esac
done < <(find "$SERVER_DIR" -maxdepth 1 -name "*.py" 2>/dev/null)

if [[ "${#orphans[@]}" -gt 0 ]]; then
  echo ""
  echo "⚠️  Orphan files in $SERVER_DIR/ — not used by this version:"
  for o in "${orphans[@]}"; do
    echo "   • $o"
  done
  echo "   Safe to remove. Run: rm $(printf "%s " "${orphans[@]/#/$SERVER_DIR/}")"
fi

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
