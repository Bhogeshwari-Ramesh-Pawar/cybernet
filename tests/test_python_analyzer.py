from cybernet.analyzers.python_ast import analyze


def rules(code, filename="app.py"):
    return {(f.rule_id, f.line): f for f in analyze(code, filename)}


def test_taint_flows_through_variables_concat_and_fstrings():
    code = (
        "import os\nfrom flask import request\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"   # 4
        "    target = host.strip()\n"             # 5
        "    cmd = f'ping {target}'\n"            # 6
        "    os.system(cmd)\n"                    # 7
    )
    f = rules(code)[("PY-CMDI-001", 7)]
    assert f.evidence.tainted and f.evidence.source == "request.args" and f.evidence.source_line == 4


def test_route_parameters_are_user_input():
    code = "@app.route('/u/<uid>')\ndef user(uid):\n    db.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
    f = rules(code)[("PY-SQLI-001", 3)]
    assert f.evidence.tainted and f.evidence.in_route and f.evidence.source == "route parameter"


def test_parameterized_query_is_not_flagged():
    code = "def q(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
    assert not rules(code)


def test_sanitizer_breaks_taint():
    code = ("import subprocess, shlex\nfrom flask import request\ndef f():\n    h = request.args['h']\n"
            "    subprocess.run('ping ' + shlex.quote(h), shell=True)\n")
    f = rules(code)[("PY-CMDI-002", 5)]
    assert not f.evidence.tainted and f.evidence.sanitized


def test_literal_command_is_marked_literal():
    f = rules("import os\nos.system('ls -la')\n")[("PY-CMDI-001", 2)]
    assert f.evidence.literal_only and not f.evidence.tainted


def test_import_aliases_are_resolved():
    code = "from os import system as run_it\nimport subprocess as sp\nrun_it(x)\nsp.call(y, shell=True)\n"
    found = rules(code)
    assert ("PY-CMDI-001", 3) in found and ("PY-CMDI-002", 4) in found


def test_list_form_subprocess_without_user_input_is_fine():
    assert not rules("import subprocess\nsubprocess.run(['git', 'status'])\n")


def test_yaml_safe_loader_is_fine_but_plain_load_is_not():
    assert not rules("import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n")
    assert ("PY-DESER-002", 2) in rules("import yaml\nyaml.load(data)\n")


def test_ssrf_path_traversal_and_xss_need_user_input():
    code = ("import requests\nfrom flask import request\n@app.route('/x')\ndef x():\n"
            "    requests.get('https://api.example.com/status')\n"   # 5 fixed URL: fine
            "    requests.get(request.args['u'])\n"                  # 6 SSRF
            "    open(request.args['f'])\n"                          # 7 path traversal
            "    return '<p>' + request.args['n'] + '</p>'\n")       # 8 XSS
    found = rules(code)
    assert ("PY-SSRF-001", 5) not in found
    assert {("PY-SSRF-001", 6), ("PY-PATH-001", 7), ("PY-XSS-001", 8)} <= set(found)


def test_weak_hash_severity_depends_on_context():
    found = rules("import hashlib\na = hashlib.md5(password.encode())\nb = hashlib.md5(file_bytes)\n")
    assert found[("PY-CRYPTO-001", 2)].severity == "high" and found[("PY-CRYPTO-001", 2)].evidence.sensitive_context
    assert found[("PY-CRYPTO-001", 3)].severity == "medium"


def test_random_only_flagged_for_secrets():
    assert ("PY-RAND-001", 2) in rules("import random\nsession_token = random.random()\n")
    assert not rules("import random\ndice = random.randint(1, 6)\n")


def test_config_issues():
    found = rules("import requests, jwt\nrequests.get(u, verify=False)\njwt.decode(t, options={'verify_signature': False})\napp.run(debug=True)\n")
    assert {("PY-TLS-001", 2), ("PY-JWT-001", 3), ("PY-CONF-001", 4)} <= set(found)


def test_no_duplicate_findings_from_nested_scopes():
    code = "import os\nclass A:\n    def m(self, x):\n        os.system(x)\n"
    assert len(analyze(code)) == 1


def test_test_files_are_marked():
    f = analyze("import os\nos.system(x)\n", "tests/test_tools.py")[0]
    assert f.evidence.in_test


def test_syntax_errors_are_reported_clearly():
    try:
        analyze("def broken(:\n")
    except ValueError as err:
        assert "line 1" in str(err)
    else:
        raise AssertionError("expected ValueError")
