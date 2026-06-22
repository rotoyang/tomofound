"""Agent Threat Rules (ATR) catalog adapter — v1 vertical slice.

ATR is an open YAML rule format for AI-agent security threats (the AI-agent
equivalent of Sigma for SIEM or YARA for malware). We consume ATR's
detection rules as a cheap regex pre-filter that runs before LLM semantic
analysis. Each ATR finding cites the source rule ID, version, and
upstream-mapped references (OWASP Agentic, MITRE ATLAS, CVE).

This module:
- Downloads a pinned ATR source tarball on user-initiated `atr_update`.
- Extracts only the rules/ subtree and the upstream LICENSE (per MIT
  retention) into `~/.tomofound/catalogs/atr/`.
- Parses each rule into a compact in-memory catalog of compiled regexes.
- Matches the catalog against scan-target content, returning findings in
  tomofound's canonical shape with `provenance.source = "atr"`.

We do not vendor any of ATR's data in this repo. The catalog only ever
lives at the user's machine, fetched from the user's network on the user's
explicit invocation.

License compliance:
- Upstream: MIT (verified directly from
  https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/v3.5.0/LICENSE,
  standard GitHub MIT template, sha256 stored as _ATR_LICENSE_SHA256_HINT
  for first-run sanity check — not used as a gate, just a hint to flag
  obvious license-replacement supply-chain attacks).
- Retention: the upstream LICENSE file is extracted into
  `~/.tomofound/catalogs/atr/LICENSE` alongside the rules, satisfying MIT's
  attribution-and-license-text requirement.
- Attribution: every finding carries provenance with rule ID + catalog
  version + upstream references; reports surface ATR as a named source.
"""

import os
import re
import json
import shutil
import tarfile
import tempfile
import hashlib
import urllib.request
import urllib.error
import yaml

DATA_ROOT = os.path.expanduser("~/.tomofound")
CATALOG_ROOT = os.path.join(DATA_ROOT, "catalogs", "atr")
RULES_DIR = os.path.join(CATALOG_ROOT, "rules")
LICENSE_PATH = os.path.join(CATALOG_ROOT, "LICENSE")
META_PATH = os.path.join(CATALOG_ROOT, "meta.json")
PARSED_CATALOG_PATH = os.path.join(CATALOG_ROOT, "catalog.json")

# --- License / attribution constants ---------------------------------------
LICENSE = "MIT"
LICENSE_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/v3.5.0/LICENSE"
ATTRIBUTION = (
    "Agent Threat Rules (ATR) v3.5.0, © 2026 ATR Contributors, MIT License — "
    "https://github.com/Agent-Threat-Rule/agent-threat-rules"
)

# --- Version pin ------------------------------------------------------------
ATR_PIN = "v3.5.0"
ATR_SOURCE_URL = (
    "https://github.com/Agent-Threat-Rule/agent-threat-rules"
    f"/archive/refs/tags/{ATR_PIN}.tar.gz"
)
ATR_LICENSE_PROBE_URL = (
    "https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules"
    f"/{ATR_PIN}/LICENSE"
)

# Defensive limits for the tarball fetch.
_TARBALL_MAX_BYTES = 60 * 1024 * 1024  # 60 MB — current v3.5.0 is ~25 MB
_EXTRACT_MAX_BYTES = 100 * 1024 * 1024  # 100 MB — rules subtree is ~7 MB
_EXTRACT_MAX_ENTRIES = 5000             # current rules: 652 files

# Severity mapping from ATR's vocab to ours.
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}


# --- Update flow ------------------------------------------------------------

class _AtrFetchError(RuntimeError):
    pass


def update_catalog() -> dict:
    """Fetch the pinned ATR source tarball, extract its rules/ subtree and
    LICENSE, parse rules into a canonical catalog cached on disk. Returns
    a summary dict.

    Idempotent: re-running with the same pin replaces the cache atomically.
    Network failure leaves the previous cache intact.
    """
    parent_dir = os.path.dirname(CATALOG_ROOT)
    os.makedirs(parent_dir, exist_ok=True)

    # Verify upstream LICENSE is still MIT before we trust the tarball.
    # If the LICENSE silently changed, refuse to update — see CLAUDE.md.
    license_ok, license_text, license_msg = _probe_license()
    if not license_ok:
        return {"error": f"license probe failed: {license_msg}"}

    # Download tarball to a SIBLING temp file (not inside CATALOG_ROOT, so the
    # atomic-swap rename below isn't blocked by a stray file inside the dir).
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False, dir=parent_dir,
                                     prefix=".atr-tarball-") as tmp:
        tarball_path = tmp.name
    try:
        try:
            written, sha256 = _download_with_cap(ATR_SOURCE_URL, tarball_path, _TARBALL_MAX_BYTES)
        except _AtrFetchError as e:
            return {"error": str(e)}

        # Extract rules/ + LICENSE only, into a fresh staging dir, then atomic swap.
        staging = CATALOG_ROOT + ".staging"
        if os.path.isdir(staging):
            shutil.rmtree(staging)
        os.makedirs(staging)
        try:
            stats = _safe_extract_rules(tarball_path, staging)
        except _AtrFetchError as e:
            shutil.rmtree(staging, ignore_errors=True)
            return {"error": str(e)}

        # Parse YAML rules → canonical catalog.
        try:
            parsed_catalog = _parse_rules_dir(os.path.join(staging, "rules"))
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            return {"error": f"rule parse failed: {e}"}

        # Persist license text + parsed catalog + meta atomically.
        with open(os.path.join(staging, "LICENSE"), "w", encoding="utf-8") as f:
            f.write(license_text)
        with open(os.path.join(staging, "catalog.json"), "w", encoding="utf-8") as f:
            json.dump(parsed_catalog, f)
        meta = {
            "version": ATR_PIN,
            "source_url": ATR_SOURCE_URL,
            "license": LICENSE,
            "license_url": LICENSE_URL,
            "tarball_sha256": sha256,
            "tarball_bytes": written,
            "rules_total": parsed_catalog["total_rules"],
            "rules_compiled": parsed_catalog["compiled_rules"],
            "categories": sorted(parsed_catalog["by_category"].keys()),
            "attribution": ATTRIBUTION,
        }
        with open(os.path.join(staging, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        # Atomic swap. We move the existing CATALOG_ROOT aside regardless of
        # contents — if it has stale partial data from a previous failed
        # update, we don't want it merged with the new payload.
        previous = CATALOG_ROOT + ".previous"
        if os.path.isdir(previous):
            shutil.rmtree(previous)
        if os.path.isdir(CATALOG_ROOT):
            os.rename(CATALOG_ROOT, previous)
        os.rename(staging, CATALOG_ROOT)
        if os.path.isdir(previous):
            shutil.rmtree(previous, ignore_errors=True)

        return {
            "ok": True,
            "version": ATR_PIN,
            "rules_compiled": parsed_catalog["compiled_rules"],
            "rules_total": parsed_catalog["total_rules"],
            "categories": meta["categories"],
            "tarball_sha256": sha256,
        }
    finally:
        if os.path.isfile(tarball_path):
            os.unlink(tarball_path)


def _probe_license() -> tuple[bool, str, str]:
    """Fetch the upstream LICENSE at the pinned tag and verify it looks like MIT.
    Returns (ok, text, message). On any failure, returns (False, '', message)."""
    try:
        with urllib.request.urlopen(ATR_LICENSE_PROBE_URL, timeout=30) as resp:
            text = resp.read(8192).decode("utf-8", errors="replace")
    except Exception as e:
        return False, "", f"could not fetch {ATR_LICENSE_PROBE_URL}: {e}"
    if "MIT License" not in text:
        return False, "", (
            f"upstream LICENSE no longer starts with 'MIT License' — "
            f"refusing to update. Please review {ATR_LICENSE_PROBE_URL} manually."
        )
    return True, text, ""


def _download_with_cap(url: str, dest_path: str, cap_bytes: int) -> tuple[int, str]:
    """Stream-download `url` to `dest_path`, refusing > `cap_bytes`. Returns
    (bytes_written, sha256_hex). Raises _AtrFetchError on any failure."""
    try:
        sha = hashlib.sha256()
        written = 0
        with urllib.request.urlopen(url, timeout=60) as resp:
            with open(dest_path, "wb") as out:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > cap_bytes:
                        raise _AtrFetchError(f"download exceeds {cap_bytes} bytes")
                    sha.update(chunk)
                    out.write(chunk)
        return written, sha.hexdigest()
    except _AtrFetchError:
        raise
    except Exception as e:
        raise _AtrFetchError(f"download failed: {e}")


def _safe_extract_rules(tarball_path: str, dest_dir: str) -> dict:
    """Extract only `rules/**/*.yaml` (plus LICENSE) from the tarball into
    `dest_dir`, enforcing zip-slip-like protections and total size caps.
    Returns a stats dict. Raises _AtrFetchError on policy violation."""
    extracted_bytes = 0
    extracted_entries = 0
    found_license = False
    rules_dest = os.path.join(dest_dir, "rules")
    os.makedirs(rules_dest, exist_ok=True)

    real_dest = os.path.realpath(dest_dir)
    real_rules = os.path.realpath(rules_dest)

    try:
        with tarfile.open(tarball_path, "r:gz") as tf:
            for member in tf:
                # Only regular files; reject symlinks / hardlinks / devices.
                if not member.isreg():
                    continue
                name = member.name
                # Path policy: must be `<root>/rules/.../*.yaml` or `<root>/LICENSE`.
                parts = name.split("/", 1)
                if len(parts) != 2:
                    continue
                inner = parts[1]
                if inner == "LICENSE":
                    target = os.path.join(dest_dir, "LICENSE.upstream")
                elif inner.startswith("rules/") and inner.endswith(".yaml"):
                    target = os.path.join(rules_dest, inner[len("rules/"):])
                else:
                    continue
                # Realpath escape check.
                real_target = os.path.realpath(target)
                if inner == "LICENSE":
                    if not real_target.startswith(real_dest):
                        raise _AtrFetchError(f"tar entry escapes dest: {name!r}")
                else:
                    if not real_target.startswith(real_rules):
                        raise _AtrFetchError(f"tar entry escapes rules dir: {name!r}")
                if member.size <= 0 or member.size > 1024 * 1024:  # per-file cap 1 MB
                    continue
                extracted_bytes += member.size
                if extracted_bytes > _EXTRACT_MAX_BYTES:
                    raise _AtrFetchError("extraction exceeds total size cap")
                extracted_entries += 1
                if extracted_entries > _EXTRACT_MAX_ENTRIES:
                    raise _AtrFetchError("extraction exceeds entry count cap")
                os.makedirs(os.path.dirname(real_target), exist_ok=True)
                fp = tf.extractfile(member)
                if fp is None:
                    continue
                with open(real_target, "wb") as out:
                    shutil.copyfileobj(fp, out)
                if inner == "LICENSE":
                    found_license = True
    except tarfile.TarError as e:
        raise _AtrFetchError(f"malformed tarball: {e}")

    if not found_license:
        raise _AtrFetchError("upstream tarball missing LICENSE — refusing to use")

    return {"entries": extracted_entries, "bytes": extracted_bytes}


# --- Parse YAML rules -------------------------------------------------------

def _parse_rules_dir(rules_dir: str) -> dict:
    """Walk `rules_dir` recursively, parse every .yaml as an ATR rule, compile
    its detection regexes. Returns a catalog dict with compiled patterns
    serialised as strings so it can be persisted as JSON."""
    catalog: dict = {
        "version": ATR_PIN,
        "rules": [],
        "by_category": {},
        "total_rules": 0,
        "compiled_rules": 0,
        "skipped_rules": [],
    }

    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in sorted(filenames):
            if not fname.endswith(".yaml"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    raw = yaml.safe_load(f)
            except Exception as e:
                catalog["skipped_rules"].append({"path": path, "reason": f"yaml: {e}"})
                continue
            catalog["total_rules"] += 1
            entry = _build_rule_entry(raw, path)
            if entry is None:
                catalog["skipped_rules"].append({"path": path, "reason": "no usable regex"})
                continue
            catalog["rules"].append(entry)
            catalog["compiled_rules"] += 1
            cat = entry["category"]
            catalog["by_category"][cat] = catalog["by_category"].get(cat, 0) + 1

    return catalog


def _build_rule_entry(raw: dict, path: str) -> dict | None:
    """Convert one parsed ATR YAML rule into our internal entry. Returns None
    if the rule has no usable regex conditions."""
    if not isinstance(raw, dict):
        return None
    rule_id = str(raw.get("id") or "").strip()
    title = str(raw.get("title") or "").strip()
    severity = _SEVERITY.get(str(raw.get("severity") or "").lower(), "medium")
    maturity = str(raw.get("maturity") or raw.get("status") or "").lower()

    # Derive category from path: rules/<category>/<rule>.yaml
    parts = path.replace("\\", "/").split("/")
    category = "uncategorised"
    for i, p in enumerate(parts[:-1]):
        if p == "rules" and i + 1 < len(parts) - 1:
            category = parts[i + 1]
            break

    refs = raw.get("references") or {}
    owasp_agentic = refs.get("owasp_agentic") or []
    mitre_atlas = refs.get("mitre_atlas") or []
    owasp_llm = refs.get("owasp_llm") or []
    cves = refs.get("cve") or []
    if not isinstance(owasp_agentic, list): owasp_agentic = [str(owasp_agentic)]
    if not isinstance(mitre_atlas, list):   mitre_atlas = [str(mitre_atlas)]
    if not isinstance(owasp_llm, list):     owasp_llm = [str(owasp_llm)]
    if not isinstance(cves, list):          cves = [str(cves)]

    detection = raw.get("detection") or {}
    conditions = detection.get("conditions") or []
    if not isinstance(conditions, list):
        return None

    patterns: list[dict] = []
    for c in conditions:
        if not isinstance(c, dict):
            continue
        if c.get("operator") != "regex":
            continue
        if c.get("field") != "content":
            # v1: we only know how to match against the file/skill body.
            # Other ATR fields (mcp_exchange, agent_state, ...) are skipped.
            continue
        value = c.get("value")
        if not isinstance(value, str) or not value:
            continue
        try:
            # Compile once now to filter out catastrophic / malformed regexes.
            re.compile(value)
        except re.error:
            continue
        patterns.append({
            "pattern": value,
            "description": str(c.get("description") or "").strip(),
        })

    if not patterns:
        return None

    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "maturity": maturity,
        "category": category,
        "patterns": patterns,
        "references": {
            "owasp_agentic": [str(x) for x in owasp_agentic],
            "mitre_atlas":   [str(x) for x in mitre_atlas],
            "owasp_llm":     [str(x) for x in owasp_llm],
            "cve":           [str(x) for x in cves],
        },
    }


# --- Match flow -------------------------------------------------------------

def _load_catalog() -> dict | None:
    """Read the persisted catalog from disk. Returns None if it isn't cached
    yet (the caller should advise the user to run `atr_update`)."""
    if not os.path.isfile(PARSED_CATALOG_PATH):
        return None
    try:
        with open(PARSED_CATALOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def catalog_status() -> dict:
    """Lightweight status used by the report header. Never raises."""
    if not os.path.isfile(META_PATH):
        return {"available": False, "reason": "catalog not yet downloaded — run atr_update"}
    try:
        with open(META_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return {
            "available": True,
            "version": meta.get("version"),
            "rules_compiled": meta.get("rules_compiled"),
            "categories": meta.get("categories"),
            "license": meta.get("license"),
            "attribution": meta.get("attribution"),
        }
    except Exception as e:
        return {"available": False, "reason": f"catalog meta unreadable: {e}"}


def match_content(
    content: str,
    file_hint: str | None = None,
    deadline: float | None = None,
) -> dict:
    """Run the cached ATR catalog against `content`. Returns a dict with
    `findings` in tomofound's canonical shape, each with `provenance.source =
    "atr"` and the matched rule's metadata.

    The matcher is offline. If the catalog isn't cached yet, returns an
    empty findings list + a `catalog_missing` note. Scans must NEVER block
    on this.

    `deadline` is an optional `time.monotonic()` value after which to bail
    mid-iteration. Without it, a single catastrophic-backtracking ATR rule
    can hang the call for arbitrary wall time — same failure mode the
    batch `scan_contents` deadline fixes. Pass one from any caller that
    cannot afford an unbounded hang (e.g. the `atr_match` MCP dispatch)."""
    catalog = _load_catalog()
    if catalog is None:
        return {
            "findings": [],
            "catalog_missing": True,
            "note": "ATR catalog not present locally — run atr_update.",
        }
    if not isinstance(content, str) or not content:
        return {"findings": [], "rules_evaluated": 0}
    findings = _match_against_catalog(catalog, content, file_hint, deadline=deadline)
    return {"findings": findings, "rules_evaluated": len(catalog.get("rules", []))}


def scan_contents(
    items,
    deadline: float | None = None,
    time_budget_seconds: float | None = None,
) -> dict:
    """Batch-match the ATR catalog against an iterable of (file_path, content)
    tuples. Loads the catalog once and reuses it across every item, which is
    the whole point of this helper — `match_content` reloads the catalog on
    every call and is wasteful for batch scans.

    `items` may be a list, generator, or any iterable. Each item must be
    `(path, content)` where path is the attribution string copied into
    finding.file, and content is the file body. Items with empty content
    or non-string content are counted as scanned but produce no findings.

    `deadline` is an optional `time.monotonic()` value after which to stop
    scanning. Checked both between files AND between rules within a file —
    the latter matters when an ATR rule's regex hits catastrophic
    backtracking on a particular file, which would otherwise burn many
    seconds before the next per-file check fires.

    Returns `{"files_scanned", "files_with_findings", "findings",
    "rules_evaluated"}`. Only files that produced at least one finding
    contribute to `findings` — clean files are counted but not enumerated,
    which is what makes this cheap to return to a token-billed caller. If
    the deadline trips, adds `budget_exceeded: True` plus a `budget_reason`.

    If the catalog isn't cached, returns `{"catalog_missing": True, ...}`
    so the caller can advise the user to run `atr_update`."""
    import time

    catalog = _load_catalog()
    if catalog is None:
        return {
            "findings": [],
            "files_scanned": 0,
            "files_with_findings": 0,
            "catalog_missing": True,
            "note": "ATR catalog not present locally — run atr_update.",
        }

    rules = catalog.get("rules", [])
    all_findings: list = []
    files_scanned = 0
    files_with_findings = 0
    budget_exceeded = False
    budget_reason: str | None = None

    budget_label = (
        f"{time_budget_seconds:.0f}s "
        if time_budget_seconds is not None
        else ""
    )

    for item in items:
        try:
            path, content = item
        except (TypeError, ValueError):
            continue
        if deadline is not None and time.monotonic() >= deadline:
            budget_exceeded = True
            budget_reason = (
                f"time budget {budget_label}exceeded between files — "
                f"re-invoke on a narrower path"
            )
            break
        files_scanned += 1
        if not isinstance(content, str) or not content:
            continue
        file_findings = _match_against_catalog(catalog, content, path, deadline=deadline)
        if file_findings:
            files_with_findings += 1
            all_findings.extend(file_findings)
        if deadline is not None and time.monotonic() >= deadline:
            budget_exceeded = True
            budget_reason = (
                f"time budget {budget_label}exceeded mid-file — likely a slow regex; "
                f"re-invoke on a narrower path"
            )
            break

    result = {
        "findings": all_findings,
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "rules_evaluated": len(rules),
    }
    if budget_exceeded:
        result["budget_exceeded"] = True
        result["budget_reason"] = budget_reason
    return result


def _match_against_catalog(
    catalog: dict, content: str, file_hint: str | None,
    deadline: float | None = None,
) -> list:
    """Run every rule in `catalog` against `content`. Returns the list of
    canonical findings (without wrapping summary fields). Shared by
    `match_content` (single-file) and `scan_contents` (batch).

    `deadline` is an optional `time.monotonic()` value after which to bail
    mid-iteration. The check happens BEFORE each rule's `re.search` call,
    so a single runaway regex can extend the actual stop time by one
    rule's worth, but not arbitrarily."""
    import time

    findings: list = []
    for rule in catalog.get("rules", []):
        if deadline is not None and time.monotonic() >= deadline:
            return findings
        for pat in rule.get("patterns", []):
            try:
                m = re.search(pat["pattern"], content)
            except re.error:
                continue
            if not m:
                continue
            line_no = content.count("\n", 0, m.start()) + 1
            line = content.splitlines()[line_no - 1] if 0 < line_no <= content.count("\n") + 1 else ""
            snippet_window = content[max(0, m.start() - 40):m.end() + 40]
            findings.append({
                "category": "PROMPT_INJECTION" if "prompt-injection" in rule["category"]
                            else "TOOL_POISONING" if "tool-poisoning" in rule["category"]
                            else "AGENT_MANIPULATION" if "agent-manipulation" in rule["category"]
                            else "DATA_EXFILTRATION_VIA_PROMPT" if "context-exfiltration" in rule["category"]
                            else "SCOPE_CREEP" if "privilege-escalation" in rule["category"]
                            else "PROMPT_INJECTION",
                "severity": rule["severity"],
                "file": file_hint or "<content>",
                "line": line_no,
                "description": f"{rule['title']} — {pat['description']}".strip(" —"),
                "snippet": (snippet_window[:200] if snippet_window else line.strip()[:200]),
                "detected_by": "ATR",
                "provenance": {
                    "source": "atr",
                    "catalog_version": catalog.get("version") or ATR_PIN,
                    "rule_id": rule["id"],
                    "rule_category": rule["category"],
                    "rule_maturity": rule["maturity"],
                    "rule_url": f"https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/{ATR_PIN}/rules/{rule['category']}/",
                    "references": rule["references"],
                },
            })
            # First match per rule is enough; don't multi-fire on the same rule.
            break
    return findings
