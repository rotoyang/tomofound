#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""
import sys, os, subprocess, json, shutil, platform, urllib.request, tempfile

VENV = os.path.expanduser("~/.claude/plugins/data/tomofound/venv")
TOOLS_DIR = os.path.expanduser("~/.claude/tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")


def find_or_install_trivy() -> str | None:
    raise NotImplementedError


def detect_scan_level(path: str) -> tuple[int, str]:
    lock_files = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
    manifest_files = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml"}
    source_extensions = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".sh", ".bash", ".zsh"}
    skip_dirs = {".git", "node_modules", "__pycache__"}

    for item in os.listdir(path):
        if item in lock_files:
            return (1, f"lock file ({item})")

    for item in os.listdir(path):
        if item in manifest_files:
            return (2, f"manifest ({item})")

    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        if os.path.isdir(item_path) and item == "node_modules":
            return (3, "node_modules directory")

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if os.path.splitext(file)[1] in source_extensions:
                return (4, "source code only")

    return (5, "no scannable content found")


def query_osv(package: str, ecosystem: str) -> dict:
    raise NotImplementedError
