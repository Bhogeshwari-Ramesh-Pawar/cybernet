from cybernet.analyzers import patterns, secrets
from cybernet.scanner import detect_language


def ids(code, lang, filename="app"):
    return {(f.rule_id, f.line): f for f in patterns.analyze(code, lang, filename)}


# ---------- JavaScript ----------

def test_js_tracks_variables_assigned_from_requests():
    code = "const name = req.query.name;\nconst msg = 'hi';\ndb.query(\"SELECT * FROM t WHERE n = '\" + name + \"'\");\n"
    f = ids(code, "javascript")[("JS-SQLI-001", 3)]
    assert f.evidence.tainted and f.evidence.source_line == 1


def test_js_template_literal_sql_and_parameterized_query():
    found = ids("db.query(`SELECT * FROM u WHERE id = ${req.params.id}`);\ndb.query('SELECT * FROM u WHERE id = ?', [id]);\n", "javascript")
    assert ("JS-SQLI-001", 1) in found and ("JS-SQLI-001", 2) not in found


def test_js_comment_and_literal_evidence():
    found = ids("// exec(req.query.cmd)\nel.innerHTML = '<b>Loading</b>';\n", "javascript")
    assert found[("JS-CMDI-001", 1)].evidence.in_comment
    assert found[("JS-XSS-001", 2)].evidence.literal_only


def test_js_input_required_rules_stay_quiet_without_input():
    assert not ids("fs.readFile('config.json', cb);\nfetch('https://api.example.com');\n", "javascript")
    assert ("JS-SSRF-001", 1) in ids("fetch(req.query.url);\n", "javascript")


def test_js_sanitizer_is_noticed():
    assert ids("el.innerHTML = DOMPurify.sanitize(html);\n", "javascript")[("JS-XSS-001", 1)].evidence.sanitized


# ---------- PHP ----------

def test_php_interpolated_variable_counts_as_tainted():
    code = "<?php\n$id = $_POST['id'];\n$pdo->query(\"SELECT * FROM t WHERE id = $id\");\n"
    assert ids(code, "php")[("PHP-SQLI-001", 3)].evidence.tainted


def test_php_escaped_output_is_marked_sanitized():
    f = ids("<?php\necho htmlspecialchars($_GET['q'], ENT_QUOTES);\n", "php")[("PHP-XSS-001", 2)]
    assert f.evidence.sanitized


# ---------- Java ----------

def test_java_sql_concat_and_multiline_crypto_context():
    code = ('String id = request.getParameter("id");\nrs = stmt.executeQuery("SELECT * FROM t WHERE id = " + id);\n'
            'MessageDigest md = MessageDigest.getInstance("MD5");\nbyte[] h = md.digest(password.getBytes());\n')
    found = ids(code, "java")
    assert found[("JAVA-SQLI-001", 2)].evidence.tainted
    assert found[("JAVA-CRYPTO-001", 3)].evidence.sensitive_context  # "password" is on the next line


# ---------- secrets ----------

def sec(code):
    return secrets.analyze(code, "python")


def test_provider_keys_are_found_and_masked():
    key = "AKIA" + "Q" * 16
    f = sec(f"aws = '{key}'\n")[0]
    assert f.rule_id == "SEC-AWS-001" and key not in f.message and key not in f.snippet


def test_generic_secret_entropy_and_placeholders():
    real = sec("db_password = 'pR7#vQ2mX9kL4tZ8wB3n'\n")[0]
    fake = sec("db_password = 'changeme'\n")[0]
    assert real.severity == "high" and real.evidence.entropy > 3.5 and not real.evidence.placeholder
    assert fake.evidence.placeholder and fake.severity == "low"


def test_secrets_read_from_environment_are_fine():
    assert not sec("password = os.environ['DB_PASSWORD']\napi_key = os.getenv('KEY')\n")


def test_connection_url_credentials():
    assert sec("url = 'postgresql://admin:S3cretPass@db:5432/app'\n")[0].rule_id == "SEC-DBURL-001"


# ---------- language detection ----------

def test_detect_language():
    assert detect_language("<?php echo 1; ?>") == "php"
    assert detect_language("def f(x):\n    return x\n") == "python"
    assert detect_language("const x = require('fs');\nmodule.exports = x;\n") == "javascript"
    assert detect_language("public class A {\n  public static void main(String[] a) { System.out.println(1); }\n}\n") == "java"
