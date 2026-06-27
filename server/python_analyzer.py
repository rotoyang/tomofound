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

# SSRF sinks — requests methods whose first positional arg is a URL.
_REQUESTS_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}

# SQL execution methods (called on cursor / connection objects).
_SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}

# LDAP search methods whose *filter* argument may be injectable.
_LDAP_SEARCH_METHODS = {"search", "search_s", "search_st", "search_ext", "search_ext_s"}

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

# Type-narrowing / value-extracting builtins. Their result cannot be used to inject code
# even when the argument is tainted (int('foo') raises, len(x) is an int, etc.), so we
# stop taint propagation here to avoid drowning real findings in noise.
_TAINT_SAFE_WRAPPERS = {
    "int", "float", "bool", "complex",
    "len", "hash", "id", "abs", "ord", "round",
    "bin", "hex", "oct",
    "isinstance", "issubclass", "type",
}

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


_NESTED_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


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

        for node in self._scope_nodes(self.function):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                self._handle_assign(node)
            elif isinstance(node, ast.Call):
                self._check_sink(node)

    def _scope_nodes(self, root):
        """DFS pre-order over `root`'s subtree that does NOT descend into nested
        function or lambda definitions. Statements appear in textual order so a
        tainting assignment is observed before a subsequent sink call."""
        for child in ast.iter_child_nodes(root):
            yield from self._descend(child)

    def _descend(self, node):
        yield node
        if isinstance(node, _NESTED_SCOPE_NODES):
            return
        for child in ast.iter_child_nodes(node):
            yield from self._descend(child)

    def _handle_assign(self, node):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:  # bare annotation, no taint change
                return
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.AugAssign):
            # x += y leaves x tainted if old x was tainted or y is tainted; can't untaint.
            if self._is_tainted(node.value) and isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
            return
        else:
            return

        value_is_tainted = self._is_tainted(value)
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                if value_is_tainted:
                    self.tainted.add(tgt.id)
                else:
                    # Safe reassignment clears taint.
                    self.tainted.discard(tgt.id)

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
            # --- SSRF: urllib.request.urlopen(tainted_url) ---
            elif (mod, attr) == ("request", "urlopen") or \
                 (mod == "urllib" and attr == "urlopen"):
                if node.args and self._is_tainted(node.args[0]):
                    self._add("high", node.lineno,
                              f"Tainted data flows into {mod}.{attr}() — SSRF")
            # --- SSRF: requests.get/post/…(tainted_url) ---
            elif mod == "requests" and attr in _REQUESTS_METHODS:
                if node.args and self._is_tainted(node.args[0]):
                    self._add("high", node.lineno,
                              f"Tainted data flows into requests.{attr}() — SSRF")
            # --- LDAP injection: ldap.search*(…, tainted_filter) ---
            elif mod == "ldap" and attr in _LDAP_SEARCH_METHODS:
                self._check_ldap_filter(node, attr)
        # --- SQL injection: <var>.execute(tainted_query) ---
        # The receiver can be any name (cursor, conn, db, etc.), so we
        # only check the method name + whether the query arg is tainted AND
        # built via string formatting/concatenation (to avoid false positives
        # on parameterized queries).
        if isinstance(func, ast.Attribute) and func.attr in _SQL_EXEC_METHODS:
            if node.args and self._is_tainted_sql(node.args[0]):
                self._add("high", node.lineno,
                          f"Tainted data flows into .{func.attr}() via string formatting — SQL injection")

    def _is_tainted_sql(self, node) -> bool:
        """Return True when a node is both tainted AND built via string
        formatting / concatenation — the hallmark of an injectable SQL query.
        Plain tainted variables that are passed with parameterized placeholders
        (``cursor.execute("SELECT ?", (val,))``) are NOT flagged."""
        if isinstance(node, ast.JoinedStr):
            # f-string — tainted if any interpolated value is tainted
            return any(
                isinstance(v, ast.FormattedValue) and self._is_tainted(v.value)
                for v in node.values
            )
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod):
                # "SELECT %s" % val  — tainted if either side is
                return self._is_tainted(node.left) or self._is_tainted(node.right)
            if isinstance(node.op, ast.Add):
                # "SELECT " + val
                return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.Call):
            # "SELECT {}".format(val)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                if any(self._is_tainted(a) for a in node.args):
                    return True
                if any(kw.value and self._is_tainted(kw.value) for kw in node.keywords):
                    return True
        if isinstance(node, ast.Name) and node.id in self.tainted:
            # A variable — only flag if we can tell from the assignment it was
            # built via formatting.  Walk the function body to find the
            # assignment and check the RHS.
            rhs = self._find_last_assignment(node.id)
            if rhs is not None:
                return self._is_tainted_sql(rhs)
        return False

    def _find_last_assignment(self, name: str):
        """Return the RHS node of the last assignment to *name* within the
        current function scope, or ``None`` if not found."""
        last = None
        for n in self._scope_nodes(self.function):
            if isinstance(n, ast.Assign):
                for tgt in n.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == name:
                        last = n.value
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                if n.value is not None:
                    last = n.value
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                # For AugAssign we treat the whole thing as a BinOp
                last = ast.BinOp(left=ast.Name(id=name), op=n.op, right=n.value)
        return last

    def _check_ldap_filter(self, node: ast.Call, attr: str):
        """Check LDAP search calls for tainted filter arguments.

        ``ldap.search_s(base, scope, filterstr, ...)`` — filterstr is the 3rd
        positional arg (index 2), or the ``filterstr`` keyword arg."""
        filter_node = None
        if len(node.args) >= 3:
            filter_node = node.args[2]
        else:
            for kw in node.keywords:
                if kw.arg == "filterstr":
                    filter_node = kw.value
                    break
        if filter_node is not None and self._is_tainted(filter_node):
            self._add("high", node.lineno,
                      f"Tainted data flows into ldap.{attr}() filter — LDAP injection")

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
            # Type-narrowing wrappers (int, len, bool, ...) yield values that can't
            # be used to inject code, so don't propagate taint through them.
            if isinstance(func, ast.Name) and func.id in _TAINT_SAFE_WRAPPERS:
                return False
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
