"""Python analyzer: AST-based sink detection with intra-procedural taint tracking.

1. Every function (and the module body) is a scope.
2. Variables assigned from user input (request.args, input(), sys.argv, route parameters, ...)
   are tainted; taint spreads through assignments, f-strings, concatenation, .format(),
   and method calls on tainted values, until it stops changing.
3. Sanitizers (shlex.quote, html.escape, int(), secure_filename, ...) clean what they wrap.
4. Dangerous calls (sinks) are reported with evidence: was the argument tainted, built
   dynamically, a fixed literal, sanitized? The ML model ranks findings from that evidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..models import Evidence, Finding

SOURCE_PREFIXES = (
    "request.args", "request.form", "request.values", "request.json", "request.get_json", "request.cookies",
    "request.headers", "request.data", "request.files", "request.GET", "request.POST", "request.body",
    "request.query_params", "request.path_params", "request.query", "sys.argv",
)
SOURCE_CALLS = {"input", "raw_input"}
SANITIZERS = {
    "shlex.quote", "pipes.quote", "html.escape", "markupsafe.escape", "flask.escape", "escape", "bleach.clean",
    "int", "float", "bool", "secure_filename", "werkzeug.utils.secure_filename", "os.path.basename",
    "urllib.parse.quote", "quote", "uuid.UUID",
}
ROUTE_DECORATORS = ("route", "get", "post", "put", "delete", "patch", "api_view")


@dataclass
class Origin:
    line: int
    source: str


def dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ""


def is_dynamic_string(node: ast.AST | None) -> bool:
    """Built at runtime: f-string, + / % with a non-constant part, or "...".format(...)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def is_literal(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(is_literal(e) for e in node.elts)
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    return False


def kw(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class Scope:
    def __init__(self, analyzer: "PythonAnalyzer", node: ast.AST, is_route: bool):
        self.a = analyzer
        self.node = node
        self.is_route = is_route
        self.tainted: dict[str, Origin] = {}
        self.sanitized_names: set[str] = set()
        if is_route and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.arg not in ("self", "cls", "request", "db", "session"):
                    self.tainted[arg.arg] = Origin(node.lineno, "route parameter")

    def nodes(self):
        """Walk this scope without descending into nested functions (they are scopes of their own)."""
        body = self.node.body if hasattr(self.node, "body") else []
        stack = [n for n in reversed(body) if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        while stack:
            n = stack.pop()
            yield n
            for child in reversed(list(ast.iter_child_nodes(n))):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                stack.append(child)

    # ---- taint ----
    def taint(self, node: ast.AST | None, track: list[bool] | None = None) -> Origin | None:
        if node is None:
            return None
        if isinstance(node, ast.Call):
            name = self.a.resolve(dotted(node.func))
            if name in SANITIZERS or name.split(".")[-1] in ("quote", "escape", "secure_filename", "basename"):
                if track is not None and any(self.taint(arg) for arg in node.args):
                    track.append(True)
                return None
            if name in SOURCE_CALLS:
                return Origin(node.lineno, f"{name}()")
            for prefix in SOURCE_PREFIXES:
                if name == prefix or name.startswith(prefix + "."):
                    return Origin(node.lineno, prefix)
            origin = self.taint(node.func, track) if isinstance(node.func, ast.Attribute) else None
            for arg in list(node.args) + [k.value for k in node.keywords]:
                origin = origin or self.taint(arg, track)
            return origin
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            name = self.a.resolve(dotted(node))
            for prefix in SOURCE_PREFIXES:
                if name == prefix or name.startswith(prefix + "."):
                    return Origin(node.lineno, prefix)
            return self.taint(node.value, track)
        if isinstance(node, ast.Name):
            if track is not None and node.id in self.sanitized_names:
                track.append(True)
            return self.tainted.get(node.id)
        children: list[ast.AST] = []
        if isinstance(node, ast.JoinedStr):
            children = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        elif isinstance(node, ast.BinOp):
            children = [node.left, node.right]
        elif isinstance(node, ast.BoolOp):
            children = node.values
        elif isinstance(node, ast.IfExp):
            children = [node.body, node.orelse]
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            children = node.elts
        elif isinstance(node, ast.Dict):
            children = [v for v in node.values if v is not None]
        elif isinstance(node, (ast.Starred, ast.FormattedValue, ast.Await)):
            children = [node.value]
        for c in children:
            o = self.taint(c, track)
            if o:
                return o
        return None

    def propagate(self) -> None:
        for _ in range(5):  # until stable
            changed = False
            for n in self.nodes():
                targets: list[ast.AST] = []
                value = None
                if isinstance(n, ast.Assign):
                    targets, value = n.targets, n.value
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    targets, value = [n.target], n.value
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    targets, value = [n.target], n.iter
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    targets, value = [n.optional_vars], n.context_expr
                if value is None:
                    continue
                sanitized: list[bool] = []
                origin = self.taint(value, sanitized)
                for t in targets:
                    for name in self._names(t):
                        if origin and name not in self.tainted:
                            self.tainted[name] = origin
                            changed = True
                        elif not origin and sanitized and name not in self.sanitized_names:
                            self.sanitized_names.add(name)
                            changed = True
            if not changed:
                return

    @staticmethod
    def _names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [n for e in target.elts for n in Scope._names(e)]
        return []


class PythonAnalyzer:
    def __init__(self, code: str, filename: str = "snippet.py"):
        self.code = code
        self.lines = code.splitlines()
        self.filename = filename
        self.in_test = _looks_like_test(filename)
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []

    def resolve(self, name: str) -> str:
        """Expand import aliases: "sp.run" → "subprocess.run", "system" → "os.system".

        Framework request objects keep their short name ("request.args"), the way developers write them.
        """
        if not name:
            return name
        head, _, rest = name.partition(".")
        if head in self.aliases:
            full = self.aliases[head]
            name = f"{full}.{rest}" if rest else full
        for framework in ("flask.", "django.http.", "starlette.requests.", "fastapi."):
            if name.startswith(framework + "request"):
                return name[len(framework):]
        return name

    def run(self) -> list[Finding]:
        try:
            tree = ast.parse(self.code)
        except SyntaxError as err:
            raise ValueError(f"Python syntax error on line {err.lineno}: {err.msg}") from err
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    self.aliases[a.asname or a.name] = f"{n.module}.{a.name}"

        scopes = [Scope(self, tree, False)]
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(Scope(self, n, _is_route(n)))
        for scope in scopes:
            scope.propagate()
            self._check(scope)
        return self.findings

    # ---- reporting ----
    def add(self, node: ast.AST, scope: Scope, rule_id: str, title: str, severity: str, category: str, cwe: str,
            owasp: str, message: str, fix: str, arg: ast.AST | None = None, **extra) -> None:
        sanitized: list[bool] = []
        origin = scope.taint(arg, sanitized) if arg is not None else None
        ev = Evidence(
            tainted=origin is not None,
            user_input=origin is not None,
            dynamic=is_dynamic_string(arg),
            literal_only=is_literal(arg) if arg is not None else False,
            sanitized=bool(sanitized),
            in_test=self.in_test,
            in_route=scope.is_route,
            source=origin.source if origin else None,
            source_line=origin.line if origin else None,
            **extra,
        )
        if origin:
            message = f"{message} User input from {origin.source} (line {origin.line}) reaches this call."
        line = getattr(node, "lineno", 1)
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, category=category, cwe=cwe, owasp=owasp,
            line=line, column=getattr(node, "col_offset", 0) + 1, message=message, fix=fix, language="python",
            snippet=self.lines[line - 1].strip() if 0 < line <= len(self.lines) else "", evidence=ev,
        ))

    def _check(self, scope: Scope) -> None:
        for n in scope.nodes():
            if isinstance(n, ast.Call):
                self._check_call(n, scope)
            elif isinstance(n, ast.Return) and scope.is_route and n.value is not None:
                self._check_reflected_xss(n, scope)

    def _check_call(self, c: ast.Call, scope: Scope) -> None:
        name = self.resolve(dotted(c.func))
        short = name.split(".")[-1]
        first = c.args[0] if c.args else None
        A = "A03:2021 Injection"

        if name in ("os.system", "os.popen", "commands.getoutput", "os.popen2"):
            self.add(c, scope, "PY-CMDI-001", "OS command injection", "critical", "injection", "CWE-78", A,
                     f"{name}() runs its argument through the system shell.",
                     "Use subprocess.run([...]) with a list of arguments and no shell; validate input against an allow-list.", first)
        elif name.startswith("subprocess.") and short in ("call", "run", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"):
            if is_true(kw(c, "shell")) or short in ("getoutput", "getstatusoutput"):
                self.add(c, scope, "PY-CMDI-002", "Command injection via shell=True", "critical", "injection", "CWE-78", A,
                         f"subprocess.{short}() with shell=True passes the command to /bin/sh.",
                         "Remove shell=True and pass the command as a list; quote with shlex.quote() only if a shell is unavoidable.", first)
            elif first is not None and scope.taint(first):
                self.add(c, scope, "PY-CMDI-003", "User-controlled program or arguments", "high", "injection", "CWE-78", A,
                         f"subprocess.{short}() is called with user-controlled arguments.",
                         "Validate the arguments against an allow-list and never let users choose the program.", first)
        elif name in ("eval", "exec", "compile", "builtins.eval", "builtins.exec"):
            self.add(c, scope, "PY-CODE-001", f"Code injection via {short}()", "critical", "injection", "CWE-95", A,
                     f"{short}() executes its argument as Python code.",
                     "Never evaluate input. Use ast.literal_eval() for literals, or json.loads() for data.", first)
        elif short in ("execute", "executemany", "raw", "executescript") or name in ("sqlalchemy.text", "text"):
            if first is not None and (is_dynamic_string(first) or (scope.taint(first) and not is_literal(first))):
                self.add(c, scope, "PY-SQLI-001", "SQL injection", "critical", "injection", "CWE-89", A,
                         "The SQL query is built with string formatting instead of bound parameters.",
                         'Use placeholders and pass values separately: cursor.execute("SELECT ... WHERE id = %s", (user_id,)).', first)
        elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "dill.loads", "marshal.loads", "shelve.open", "jsonpickle.decode"):
            self.add(c, scope, "PY-DESER-001", "Insecure deserialization", "high", "deserialization", "CWE-502",
                     "A08:2021 Software and Data Integrity Failures",
                     f"{name}() can execute arbitrary code when given crafted data.",
                     "Use json for untrusted data; if you must use pickle, sign payloads with hmac and verify before loading.", first)
        elif name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"):
            loader = kw(c, "Loader") or (c.args[1] if len(c.args) > 1 else None)
            if name == "yaml.unsafe_load" or not (loader is not None and "Safe" in dotted(loader)):
                self.add(c, scope, "PY-DESER-002", "Unsafe YAML loading", "high", "deserialization", "CWE-502",
                         "A08:2021 Software and Data Integrity Failures",
                         "yaml.load() without SafeLoader can construct arbitrary Python objects.",
                         "Use yaml.safe_load(data).", first)
        elif name in ("open", "io.open", "flask.send_file", "send_file", "send_from_directory", "os.remove", "shutil.rmtree"):
            path_arg = c.args[-1] if name.endswith("send_from_directory") and c.args else first
            if path_arg is not None and scope.taint(path_arg):
                self.add(c, scope, "PY-PATH-001", "Path traversal", "high", "path_ssrf", "CWE-22", "A01:2021 Broken Access Control",
                         f"{short}() uses a file path built from user input (../../etc/passwd).",
                         "Use werkzeug.utils.secure_filename() or resolve the path and check it stays inside an allowed directory.", path_arg)
        elif name.split(".")[0] in ("requests", "httpx", "urllib", "urllib3", "aiohttp") and short in (
                "get", "post", "put", "delete", "head", "request", "urlopen", "patch"):
            verify = kw(c, "verify")
            if is_false(verify):
                self.add(c, scope, "PY-TLS-001", "TLS certificate verification disabled", "medium", "config", "CWE-295",
                         "A07:2021 Identification and Authentication Failures",
                         "verify=False accepts any certificate, allowing man-in-the-middle attacks.",
                         "Remove verify=False; point verify= at your CA bundle for internal certificates.", verify)
            url = first if first is not None else kw(c, "url")
            if url is not None and scope.taint(url):
                self.add(c, scope, "PY-SSRF-001", "Server-side request forgery (SSRF)", "high", "path_ssrf", "CWE-918",
                         "A10:2021 Server-Side Request Forgery",
                         "The server fetches a URL controlled by the user, which can reach internal services and cloud metadata.",
                         "Allow-list hosts/schemes, resolve the hostname and block private and link-local ranges.", url)
        elif name in ("flask.render_template_string", "render_template_string", "jinja2.Template", "Template"):
            if first is not None and not is_literal(first):
                self.add(c, scope, "PY-SSTI-001", "Server-side template injection", "critical", "injection", "CWE-1336", A,
                         "A template is rendered from a dynamic string, so template syntax in user input runs on the server.",
                         "Render a fixed template file with render_template() and pass user data as variables.", first)
        elif name in ("markupsafe.Markup", "Markup", "flask.Markup") and first is not None and not is_literal(first):
            self.add(c, scope, "PY-XSS-002", "Cross-site scripting via Markup()", "high", "xss", "CWE-79", "A03:2021 Injection",
                     "Markup() marks the string as safe HTML, so it is not escaped.",
                     "Pass user data to the template unescaped by you; let Jinja2 autoescape it.", first)
        elif name in ("hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "md5", "sha1") or (
                name == "hashlib.new" and first is not None and isinstance(first, ast.Constant) and str(first.value).lower() in ("md5", "sha1")):
            text = ast.unparse(c).lower()
            sensitive = any(w in text for w in ("password", "passwd", "pwd", "secret", "token"))
            self.add(c, scope, "PY-CRYPTO-001", "Weak hash algorithm (MD5/SHA-1)", "high" if sensitive else "medium", "crypto",
                     "CWE-327", "A02:2021 Cryptographic Failures",
                     "MD5 and SHA-1 are broken for security use" + (" and must never hash passwords." if sensitive else "."),
                     "Hash passwords with bcrypt/argon2 (e.g. passlib); use hashlib.sha256 for integrity checks.",
                     None, sensitive_context=sensitive)
        elif name.startswith("random.") and short in ("random", "randint", "choice", "randrange", "getrandbits", "choices"):
            target = self._assigned_name(c)
            if target and any(w in target.lower() for w in ("token", "secret", "password", "otp", "key", "nonce", "salt", "session")):
                self.add(c, scope, "PY-RAND-001", "Insecure randomness for a secret", "medium", "crypto", "CWE-338",
                         "A02:2021 Cryptographic Failures",
                         f"random.{short}() is predictable; '{target}' looks security-sensitive.",
                         "Use the secrets module: secrets.token_urlsafe(32), secrets.randbelow(n).", None, sensitive_context=True)
        elif short == "run" and is_true(kw(c, "debug")):
            self.add(c, scope, "PY-CONF-001", "Debug mode enabled", "medium", "config", "CWE-489",
                     "A05:2021 Security Misconfiguration",
                     "Flask debug mode exposes an interactive debugger that allows remote code execution.",
                     "Never enable debug in production; read it from an environment variable that defaults to False.", kw(c, "debug"))
        elif name == "tempfile.mktemp":
            self.add(c, scope, "PY-TEMP-001", "Insecure temporary file", "low", "config", "CWE-377",
                     "A05:2021 Security Misconfiguration", "mktemp() has a race between choosing the name and creating the file.",
                     "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp().", None)
        elif name in ("jwt.decode",):
            options = kw(c, "options")
            if is_false(kw(c, "verify")) or (options is not None and "verify_signature" in ast.unparse(options) and "False" in ast.unparse(options)):
                self.add(c, scope, "PY-JWT-001", "JWT signature not verified", "high", "config", "CWE-347",
                         "A07:2021 Identification and Authentication Failures",
                         "Tokens are decoded without checking the signature, so anyone can forge them.",
                         "Always verify: jwt.decode(token, key, algorithms=['HS256']).", None)

    def _check_reflected_xss(self, r: ast.Return, scope: Scope) -> None:
        value = r.value
        html = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and "<" in n.value for n in ast.walk(value))
        if html and is_dynamic_string(value) and scope.taint(value):
            self.add(r, scope, "PY-XSS-001", "Reflected cross-site scripting", "high", "xss", "CWE-79", "A03:2021 Injection",
                     "User input is placed into an HTML response without escaping.",
                     "Render a template (autoescaped) or wrap values with markupsafe.escape().", value)

    def _assigned_name(self, call: ast.Call) -> str | None:
        """Name of the variable/attribute/key the call's result is stored in, e.g. "reset_token"."""
        line = self.lines[call.lineno - 1] if 0 < call.lineno <= len(self.lines) else ""
        left, eq, _ = line.partition("=")
        if not eq or left.rstrip().endswith(("!", "<", ">", "=")):
            return None
        left = left.strip().rstrip(":").split(":")[0]  # drop annotations
        return left.split()[-1] if left else None


def _is_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in fn.decorator_list:
        name = dotted(d)
        if name.split(".")[-1] in ROUTE_DECORATORS:
            return True
    return False


def _looks_like_test(filename: str) -> bool:
    f = filename.replace("\\", "/").lower()
    base = f.rsplit("/", 1)[-1]
    return "/tests/" in f or "/test/" in f or f.startswith(("tests/", "test/")) or base.startswith("test_") or base.endswith(
        ("_test.py", ".test.js", ".spec.js", "test.java", "_test.php"))


def analyze(code: str, filename: str = "snippet.py") -> list[Finding]:
    return PythonAnalyzer(code, filename).run()
