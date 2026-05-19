#!/usr/bin/env python3
"""Trivy MCP server for tomofound security-scan skill."""
import sys, os, subprocess, json, shutil, platform, urllib.request, tempfile

VENV = os.path.expanduser("~/.claude/plugins/data/tomofound/venv")
TOOLS_DIR = os.path.expanduser("~/.claude/tools")
TOOLS_TRIVY = os.path.join(TOOLS_DIR, "trivy")


def find_or_install_trivy() -> str | None:
    raise NotImplementedError


def detect_scan_level(path: str) -> tuple[int, str]:
    raise NotImplementedError


def query_osv(package: str, ecosystem: str) -> dict:
    raise NotImplementedError
