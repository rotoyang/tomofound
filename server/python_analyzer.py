"""Static analysis for Python files in AI tool extensions.

Two passes per file:

1. AST risk scan — flags direct uses of dangerous APIs (`eval`, `exec`, `pickle.loads`,
   `subprocess.run(shell=True)`, etc.) and string-obfuscated dynamic dispatch
   (`getattr(x, "ev" + "al")`).

2. Lightweight intraprocedural taint tracking — within each function, marks variables
   tainted when assigned from a known untrusted source (env vars, `sys.argv`, `input`,
   `os.environ`, `requests.get(...)`, `urlopen(...)`, MCP tool handler parameters),
   propagates through assignments / f-strings / concatenation, and reports when tainted
   data reaches a sink (`eval`, `exec`, `compile`, `os.system`, `os.popen`,
   `subprocess.*(shell=True)`).

Findings use the same shape as Trivy / LLM findings — `category`, `severity`, `file`,
`line`, `description`, `snippet` — plus `detected_by: "AST" | "TAINT"`.
"""

import ast
import os


_RISKY_BUILTINS = {
    "eval":       ("BACKDOOR", "critical", "Dynamic code evaluation via eval()"),
    "exec":       ("BACKDOOR", "critical", "Dynamic code execution via exec()"),
    "compile":    ("BACKDOOR", "high",     "Runtime code compilation via compile()"),
    "__import__": ("BACKDOOR", "high",     "Dynamic import via __import__"),
}

_RISKY_ATTRS = {
    ("pickle",  "loads"): ("BACKDOOR", "critical", "Untrusted pickle deserialization"),
    ("pickle",  "load"):  ("BACKDOOR", "critical", "Untrusted pickle deserialization"),
    ("cPickle", "loads"): ("BACKDOOR", "critical", "Untrusted pickle deserialization"),
    ("marshal", "loads"): ("BACKDOOR", "high",     "Untrusted marshal deserialization"),
    ("yaml",    "load"):  ("BACKDOOR", "high",     "Unsafe yaml.load (use safe_load)"),
    ("os",      "system"): ("BACKDOOR", "high",    "Shell command via os.system()"),
    ("os",      "popen"):  ("BACKDOOR", "high",    "Shell command via os.popen()"),
}

_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}

_TAINT_SOURCE_ATTRS = {
    ("os",  "environ"),
    ("os",  "getenv"),
    ("sys", "argv"),
}

_TAINT_SOURCE_CALLS = {
    ("urllib", "urlopen"),
    ("requests", "get"),
    ("requests", "post"),
}

_TAINT_SOURCE_BUILTINS = {"input"}

_MCP_DECORATOR_ATTRS = {"call_tool", "list_tools", "list_prompts", "get_prompt", "list_resources"}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", "out"}

_FILE_SIZE_LIMIT = 1024 * 1024  # 1 MB


def analyze_python(path: str) -> dict:
    abs_path = os.path.abspath(os.path.expanduser(path))
    findings: list = []
    files_analyzed = 0
    skipped: list = []

    if os.path.isfile(abs_path):
        targets = [abs_path] if abs_path.endswith(".py") else []
        if not targets:
            return {"findings": [], "files_analyzed": 0, "skipped": [{"path": abs_path, "reason": "not a .py file"}]}
    elif os.path.isdir(abs_path):
        targets = []
        for dirpath, dirs, files in os.walk(abs_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                if fname.endswith(".py"):
                    targets.append(os.path.join(dirpath, fname))
    else:
        return {"error": "path not found"}

    for fpath in targets:
        try:
            size = os.path.getsize(fpath)
        except OSError as e:
            skipped.append({"path": fpath, "reason": f"stat error: {e}"})
            continue
        if size > _FILE_SIZE_LIMIT:
            skipped.append({"path": fpath, "reason": f"file exceeds {_FILE_SIZE_LIMIT} bytes"})
            continue
        result = _analyze_file(fpath)
        if "skipped" in result:
            skipped.append({"path": fpath, "reason": result["skipped"]})
        else:
            findings.extend(result["findings"])
            files_analyzed += 1

    return {"findings": findings, "files_analyzed": files_analyzed, "skipped": skipped}


def _analyze_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        return {"skipped": f"read error: {e}"}
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return {"skipped": f"syntax error at line {e.lineno}"}

    lines = source.splitlines()
    findings: list = []

    risk = _RiskVisitor(path, lines)
    risk.visit(tree)
    findings.extend(risk.findings)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            taint = _TaintVisitor(path, lines, node)
            taint.run()
            findings.extend(taint.findings)

    return {"findings": findings}


def _snippet(lines: list, lineno: int) -> str:
    if not lines or lineno < 1 or lineno > len(lines):
        return ""
    return lines[lineno - 1].strip()


class _RiskVisitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list):
        self.path = path
        self.lines = lines
        self.findings: list = []

    def _add(self, category, severity, line, description):
        self.findings.append({
            "category": category,
            "severity": severity,
            "file": self.path,
            "line": line,
            "description": description,
            "snippet": _snippet(self.lines, line),
            "detected_by": "AST",
        })

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _RISKY_BUILTINS:
                cat, sev, desc = _RISKY_BUILTINS[func.id]
                self._add(cat, sev, node.lineno, desc)
            elif func.id == "getattr" and len(node.args) >= 2:
                second = node.args[1]
                if isinstance(second, (ast.BinOp, ast.JoinedStr)):
                    self._add("BACKDOOR", "medium", node.lineno,
                              "Dynamic attribute access built from concatenated/formatted string (possible obfuscation)")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            mod, attr = func.value.id, func.attr
            if (mod, attr) in _RISKY_ATTRS:
                cat, sev, desc = _RISKY_ATTRS[(mod, attr)]
                self._add(cat, sev, node.lineno, desc)
            elif mod == "subprocess" and attr in _SUBPROCESS_FUNCS:
                if _has_shell_true(node):
                    self._add("BACKDOOR", "high", node.lineno,
                              f"subprocess.{attr} called with shell=True")
        self.generic_visit(node)


def _has_shell_true(call_node: ast.Call) -> bool:
    for kw in call_node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_mcp_handler(func_def) -> bool:
    for dec in func_def.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in _MCP_DECORATOR_ATTRS:
            return True
    return False


class _TaintVisitor:
    def __init__(self, path: str, lines: list, function):
        self.path = path
        self.lines = lines
        self.function = function
        self.findings: list = []
        self.tainted: set = set()

    def _add(self, severity, line, description):
        self.findings.append({
            "category": "BACKDOOR",
            "severity": severity,
            "file": self.path,
            "line": line,
            "description": description,
            "snippet": _snippet(self.lines, line),
            "detected_by": "TAINT",
        })

    def run(self):
        if _is_mcp_handler(self.function):
            for a in self.function.args.args:
                self.tainted.add(a.arg)
            for a in self.function.args.kwonlyargs:
                self.tainted.add(a.arg)

        for stmt in ast.walk(self.function):
            if isinstance(stmt, ast.Assign):
                self._handle_assign(stmt)
            elif isinstance(stmt, ast.Call):
                self._check_sink(stmt)

    def _handle_assign(self, node: ast.Assign):
        if self._is_tainted(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.tainted.add(tgt.id)

    def _check_sink(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"eval", "exec", "compile"}:
            if node.args and self._is_tainted(node.args[0]):
                self._add("critical", node.lineno,
                          f"Tainted data flows into {func.id}() — possible code injection")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            mod, attr = func.value.id, func.attr
            if (mod, attr) in {("os", "system"), ("os", "popen")}:
                if node.args and self._is_tainted(node.args[0]):
                    self._add("critical", node.lineno,
                              f"Tainted data flows into {mod}.{attr}() — shell injection")
            elif mod == "subprocess" and attr in _SUBPROCESS_FUNCS:
                if _has_shell_true(node) and node.args and self._is_tainted(node.args[0]):
                    self._add("critical", node.lineno,
                              f"Tainted data flows into subprocess.{attr}(shell=True) — shell injection")

    def _is_tainted(self, node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and (node.value.id, node.attr) in _TAINT_SOURCE_ATTRS:
                return True
            return self._is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _TAINT_SOURCE_BUILTINS:
                return True
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                pair = (func.value.id, func.attr)
                if pair in _TAINT_SOURCE_ATTRS or pair in _TAINT_SOURCE_CALLS:
                    return True
                # Chains: requests.get(...).text / .json()
                if self._is_tainted(func.value):
                    return True
            return any(self._is_tainted(a) for a in node.args)
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and self._is_tainted(v.value)
                for v in node.values
            )
        return False
