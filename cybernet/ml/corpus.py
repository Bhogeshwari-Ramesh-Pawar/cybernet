"""Labelled training corpus for the prioritizer.

Each template is code the scanner flags, labelled by a security reviewer's judgement:
  1 = real and exploitable / must fix      0 = false positive or no real risk
Variants randomize identifiers and file names (and move code into tests or comments,
which changes the label), so the model learns from evidence rather than exact text.
The scanner itself extracts the features: training uses the same code path as real scans.

Note: PHP examples that resemble web shells (eval/system/include on request data) are
deliberately left out. Antivirus products flag them, which would make this project
impossible to clone on a normal developer machine.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass

VARS = ["host", "target", "name", "q", "query", "user_id", "uid", "item", "path", "fname", "url", "cmd", "data", "value", "term"]
FUNCS = ["handler", "view", "lookup", "search", "download", "ping", "profile", "export_data", "process", "load_item"]


def _rand_key(prefix: str, n: int, alphabet: str = string.ascii_letters + string.digits, rnd: random.Random | None = None) -> str:
    rnd = rnd or random.Random()
    return prefix + "".join(rnd.choice(alphabet) for _ in range(n))


@dataclass
class Template:
    language: str
    label: int
    code: str
    test_label: int | None = 0      # label when the same code sits in a test file (None: no test variant)
    comment_variant: bool = False   # also emit it commented out (always label 0)


# {v} variable, {f} function, {k} random secret — filled per variant
PY = [
    Template("python", 1, "from flask import request\nimport os\n@app.route('/x')\ndef {f}():\n    {v} = request.args.get('{v}')\n    os.system('ping -c 1 ' + {v})\n"),
    Template("python", 1, "import subprocess\nfrom flask import request\n@app.post('/x')\ndef {f}():\n    {v} = request.form['{v}']\n    subprocess.run(f'nslookup {{{v}}}', shell=True)\n"),
    Template("python", 1, "@app.route('/u/<{v}>')\ndef {f}({v}):\n    db.execute(f\"SELECT * FROM users WHERE id = {{{v}}}\")\n"),
    Template("python", 1, "from flask import request\ndef {f}():\n    {v} = request.args['{v}']\n    cur.execute(\"SELECT * FROM t WHERE name = '%s'\" % {v})\n"),
    Template("python", 1, "from flask import request\nimport pickle\n@app.post('/load')\ndef {f}():\n    return pickle.loads(request.data)\n"),
    Template("python", 1, "from flask import request\nimport yaml\ndef {f}():\n    cfg = yaml.load(request.data)\n"),
    Template("python", 1, "from flask import request, render_template_string\n@app.route('/p')\ndef {f}():\n    return render_template_string(request.args.get('{v}'))\n"),
    Template("python", 1, "from flask import request\n@app.route('/f')\ndef {f}():\n    return open(request.args.get('{v}')).read()\n"),
    Template("python", 1, "import requests\nfrom flask import request\n@app.route('/fetch')\ndef {f}():\n    return requests.get(request.args['{v}']).text\n"),
    Template("python", 1, "from flask import request\n@app.post('/calc')\ndef {f}():\n    expr = request.form['{v}']\n    return str(eval(expr))\n"),
    Template("python", 1, "from flask import request\n@app.route('/hi')\ndef {f}():\n    {v} = request.args.get('{v}', '')\n    return '<h1>Hello ' + {v} + '</h1>'\n"),
    Template("python", 1, "import hashlib\ndef {f}(password):\n    return hashlib.md5(password.encode()).hexdigest()\n"),
    Template("python", 1, "import random\ndef {f}():\n    reset_token = random.randint(100000, 999999)\n    return reset_token\n"),
    Template("python", 1, "import jwt\ndef {f}(t):\n    return jwt.decode(t, options={{'verify_signature': False}})\n"),
    Template("python", 1, "import requests\ndef {f}(u):\n    return requests.get(u, verify=False)\n"),
    Template("python", 1, "app.run(host='0.0.0.0', debug=True)\n", test_label=None),
    Template("python", 1, "AWS_KEY = '{aws}'\n", test_label=1),
    Template("python", 1, "GITHUB_TOKEN = '{gh}'\n", test_label=1),
    Template("python", 1, "db_password = '{k}'\n", test_label=1),
    Template("python", 1, "DATABASE_URL = 'postgresql://admin:{k}@db.internal:5432/prod'\n", test_label=1),
    # --- flagged by the rules, but not a real risk ---
    Template("python", 0, "import os\ndef {f}():\n    os.system('ls -la /var/log')\n", test_label=None),
    Template("python", 0, "import subprocess\nsubprocess.run('git status', shell=True)\n", test_label=None),
    Template("python", 0, "import subprocess, shlex\nfrom flask import request\ndef {f}():\n    {v} = request.args.get('{v}')\n    subprocess.run('ping -c 1 ' + shlex.quote({v}), shell=True)\n", test_label=None),
    Template("python", 0, "TABLE = 'audit_log'\ndef {f}(cur):\n    cur.execute(f'SELECT COUNT(*) FROM {{TABLE}}')\n", test_label=None),
    Template("python", 0, "def {f}():\n    return eval('2 + 2')\n", test_label=None),
    Template("python", 0, "import hashlib\ndef {f}(content):\n    etag = hashlib.md5(content).hexdigest()\n    return etag\n", test_label=None),
    Template("python", 0, "import hashlib\ncache_key = hashlib.sha1(b'static-asset-v2').hexdigest()\n", test_label=None),
    Template("python", 0, "password = 'changeme'\n", test_label=None),
    Template("python", 0, "API_KEY = 'your-api-key-here'\n", test_label=None),
    Template("python", 0, "secret = '<insert-secret>'\n", test_label=None),
    Template("python", 0, "import tempfile\nf = tempfile.mktemp()\n", test_label=None),
    Template("python", 0, "import pickle\nwith open('model.pkl', 'rb') as fh:\n    m = pickle.load(fh)\n", test_label=None),
]

JS = [
    Template("javascript", 1, "app.get('/calc', (req, res) => {{\n  const expr = req.query.{v};\n  res.send(String(eval(expr)));\n}});\n", comment_variant=True),
    Template("javascript", 1, "const {{ exec }} = require('child_process');\napp.get('/ping', (req, res) => {{\n  exec(`ping -c 1 ${{req.query.{v}}}`);\n}});\n", comment_variant=True),
    Template("javascript", 1, "app.get('/u/:id', async (req, res) => {{\n  const rows = await db.query(`SELECT * FROM users WHERE id = ${{req.params.id}}`);\n}});\n"),
    Template("javascript", 1, "const {v} = req.body.{v};\ndb.query(\"SELECT * FROM t WHERE name = '\" + {v} + \"'\");\n"),
    Template("javascript", 1, "document.getElementById('out').innerHTML = location.hash.slice(1);\n", comment_variant=True),
    Template("javascript", 1, "const {v} = new URLSearchParams(location.search).get('{v}');\nel.innerHTML = '<p>' + {v} + '</p>';\n"),
    Template("javascript", 1, "app.get('/hi', (req, res) => {{\n  res.send('<h1>Hello ' + req.query.{v} + '</h1>');\n}});\n"),
    Template("javascript", 1, "app.get('/file', (req, res) => {{\n  fs.readFile(req.query.{v}, (e, d) => res.send(d));\n}});\n"),
    Template("javascript", 1, "app.get('/proxy', async (req, res) => {{\n  const r = await fetch(req.query.{v});\n}});\n"),
    Template("javascript", 1, "app.get('/login', (req, res) => {{\n  res.redirect(req.query.next);\n}});\n"),
    Template("javascript", 1, "app.post('/settings', (req, res) => {{\n  _.merge(config, req.body);\n}});\n"),
    Template("javascript", 1, "const hash = crypto.createHash('md5').update(password).digest('hex');\n"),
    Template("javascript", 1, "const resetToken = Math.random().toString(36).slice(2);\n"),
    Template("javascript", 1, "const payload = jwt.decode(req.headers.authorization);\n"),
    Template("javascript", 1, "const agent = new https.Agent({{ rejectUnauthorized: false }});\n"),
    Template("javascript", 1, "const stripe = require('stripe')('{stripe}');\n", test_label=1),
    Template("javascript", 1, "const apiKey = '{k}';\n", test_label=1),
    Template("javascript", 0, "exec('ls -la', (e, out) => console.log(out));\n", test_label=None),
    Template("javascript", 0, "el.innerHTML = '<span class=\"spinner\">Loading…</span>';\n", test_label=None),
    Template("javascript", 0, "el.innerHTML = DOMPurify.sanitize(html);\n", test_label=None),
    Template("javascript", 0, "const etag = crypto.createHash('md5').update(fileBuffer).digest('hex');\n", test_label=None),
    Template("javascript", 0, "const password = 'changeme';\n", test_label=None),
    Template("javascript", 0, "app.use(cors({{ origin: '*' }}));\n", test_label=None),
    Template("javascript", 0, "setTimeout('refresh()', 1000);\n", test_label=None),
]

PHP = [
    Template("php", 1, "<?php\n$r = mysqli_query($conn, \"SELECT * FROM users WHERE id = \" . $_GET['id']);\n"),
    Template("php", 1, "<?php\n$id = $_POST['id'];\n$pdo->query(\"SELECT * FROM t WHERE id = $id\");\n"),
    Template("php", 1, "<?php\n$name = $_POST['{v}'];\n$rows = $db->query(\"SELECT * FROM products WHERE name = '\" . $name . \"'\");\n"),
    Template("php", 1, "<?php\necho \"Hello \" . $_GET['{v}'];\n"),
    Template("php", 1, "<?php\n$q = $_GET['{v}'];\nprint \"<p>Results for $q</p>\" . $_GET['{v}'];\n"),
    Template("php", 1, "<?php\n$data = unserialize($_COOKIE['prefs']);\n"),
    Template("php", 1, "<?php\n$hash = md5($password);\n"),
    Template("php", 1, "<?php\n$token = sha1($password . $salt);\n"),
    Template("php", 1, "<?php\n$db_password = '{k}';\n", test_label=1),
    Template("php", 0, "<?php\necho htmlspecialchars($_GET['{v}'], ENT_QUOTES, 'UTF-8');\n", test_label=None),
    Template("php", 0, "<?php\n$r = mysqli_query($conn, 'SELECT COUNT(*) FROM posts');\n", test_label=None),
    Template("php", 0, "<?php\n$cacheKey = md5('sidebar-widget-v3');\n", test_label=None),
    Template("php", 0, "<?php\n$id = uniqid();\n", test_label=None),
    Template("php", 0, "<?php\n$password = 'changeme';\n", test_label=None),
    Template("php", 0, "<?php\n// $rows = $db->query(\"SELECT * FROM t WHERE id = \" . $id);\n", test_label=None),
]

JAVA = [
    Template("java", 1, "String id = request.getParameter(\"id\");\nResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + id);\n"),
    Template("java", 1, "String {v} = request.getParameter(\"{v}\");\nString sql = \"SELECT * FROM orders WHERE ref = '\" + {v} + \"'\";\n"),
    Template("java", 1, "ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nObject o = in.readObject();\n"),
    Template("java", 1, "response.getWriter().println(\"Hello \" + request.getParameter(\"{v}\"));\n"),
    Template("java", 1, "MessageDigest md = MessageDigest.getInstance(\"MD5\");\nbyte[] h = md.digest(password.getBytes());\n"),
    Template("java", 1, "Cipher c = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"),
    Template("java", 1, "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocument d = dbf.newDocumentBuilder().parse(request.getInputStream());\n"),
    Template("java", 1, "String f = request.getParameter(\"file\");\nFileInputStream in = new FileInputStream(\"/data/\" + f);\n"),
    Template("java", 1, "public void checkServerTrusted(X509Certificate[] c, String a) {{ }}\n"),
    Template("java", 1, "private static final String SECRET_KEY = \"{k}\";\n", test_label=1),
    Template("java", 0, "Process p = new ProcessBuilder(\"git\", \"status\").start();\n", test_label=None),
    Template("java", 0, "Collections.shuffle(cards, new Random());\n", test_label=None),
    Template("java", 0, "response.getWriter().println(Encode.forHtml(request.getParameter(\"{v}\")));\n", test_label=None),
    Template("java", 0, "MessageDigest md = MessageDigest.getInstance(\"SHA-1\"); // file checksum for cache busting\n", test_label=None),
    Template("java", 0, "String password = \"changeme\";\n", test_label=None),
    Template("java", 0, "// ResultSet rs = stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n", test_label=None),
]

TEMPLATES = PY + JS + PHP + JAVA
COMMENT = {"python": "# ", "javascript": "// ", "php": "// ", "java": "// "}
EXT = {"python": "py", "javascript": "js", "php": "php", "java": "java"}
TEST_FILE = {"python": "tests/test_api.py", "javascript": "api.test.js", "php": "tests/ApiTest_test.php", "java": "src/test/ApiTest.java"}


def _fill(t: Template, rnd: random.Random) -> str:
    return t.code.format(
        v=rnd.choice(VARS), f=rnd.choice(FUNCS),
        k=_rand_key("", rnd.randint(16, 32), string.ascii_letters + string.digits + "+/_-", rnd),
        aws=_rand_key("AKIA", 16, string.ascii_uppercase + string.digits, rnd),
        gh=_rand_key("ghp_", 36, rnd=rnd), stripe=_rand_key("sk_live_", 24, rnd=rnd),
    )


def build(variants: int = 8, seed: int = 42) -> list[tuple[str, str, str, int, int]]:
    """Return (language, filename, code, label, template_index) samples."""
    rnd = random.Random(seed)
    out = []
    for idx, t in enumerate(TEMPLATES):
        ext = EXT[t.language]
        for _ in range(variants):
            name = rnd.choice([f"app.{ext}", f"src/{rnd.choice(FUNCS)}.{ext}", f"api/routes.{ext}"])
            out.append((t.language, name, _fill(t, rnd), t.label, idx))
        if t.test_label is not None:
            for _ in range(max(2, variants // 3)):
                out.append((t.language, TEST_FILE[t.language], _fill(t, rnd), t.test_label, idx))
        if t.comment_variant:
            for _ in range(max(2, variants // 3)):
                lines = _fill(t, rnd).splitlines()
                commented = "\n".join(ln if ln.startswith("<?php") else COMMENT[t.language] + ln for ln in lines) + "\n"
                out.append((t.language, f"app.{ext}", commented, 0, idx))
    return out
