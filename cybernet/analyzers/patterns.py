"""Rule-based analyzer for JavaScript/Node.js, PHP and Java.

Each rule is a regex for a dangerous construct. For every match we also collect evidence:
  - user input on the line (req.query, $_GET, request.getParameter, ...) or a variable
    previously assigned from user input (light, line-ordered taint tracking)
  - the argument is built dynamically (concatenation, template literal, "$var" interpolation)
  - the argument is a fixed literal, or a sanitizer / prepared statement is used
  - the match sits in a comment, or in a test file
The ML prioritizer turns that evidence into a confidence score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Evidence, Finding
from .python_ast import _looks_like_test

A03 = "A03:2021 Injection"
A02 = "A02:2021 Cryptographic Failures"
A05 = "A05:2021 Security Misconfiguration"
A08 = "A08:2021 Software and Data Integrity Failures"
A07 = "A07:2021 Identification and Authentication Failures"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: str
    severity: str
    category: str
    cwe: str
    owasp: str
    message: str
    fix: str
    requires_input: bool = False  # only report when user input is involved (otherwise too noisy)
    flags: int = 0

    @property
    def regex(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)


JS_RULES = [
    Rule("JS-CODE-001", "Code injection via eval()", r"\beval\s*\(", "critical", "injection", "CWE-95", A03,
         "eval() executes a string as JavaScript.", "Remove eval(); parse data with JSON.parse()."),
    Rule("JS-CODE-002", "Code injection via Function constructor", r"\bnew\s+Function\s*\(", "critical", "injection", "CWE-95", A03,
         "new Function() compiles a string into code.", "Avoid building code from strings."),
    Rule("JS-CODE-003", "String passed to setTimeout/setInterval", r"\bset(?:Timeout|Interval)\s*\(\s*(['\"`]|[a-zA-Z_$][\w$]*\s*\+)", "medium",
         "injection", "CWE-95", A03, "A string argument to setTimeout/setInterval is evaluated as code.", "Pass a function instead of a string."),
    Rule("JS-CMDI-001", "OS command injection", r"\b(?:child_process\.)?(?:exec|execSync)\s*\(", "critical", "injection", "CWE-78", A03,
         "exec() runs the command through a shell.", "Use execFile()/spawn() with an argument array and no shell; allow-list inputs."),
    Rule("JS-CMDI-002", "spawn() with shell: true", r"\bspawn(?:Sync)?\s*\(.*shell\s*:\s*true", "high", "injection", "CWE-78", A03,
         "spawn() with shell: true interprets the command in a shell.", "Remove shell: true and pass arguments as an array."),
    Rule("JS-SQLI-001", "SQL injection", r"\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+|'[^']*(?:SELECT|INSERT|UPDATE|DELETE)[^']*'\s*\+)",
         "critical", "injection", "CWE-89", A03, "The SQL query is built from strings instead of bound parameters.",
         "Use placeholders: db.query('SELECT * FROM users WHERE id = ?', [id]).", flags=re.I),
    Rule("JS-NOSQL-001", "NoSQL injection", r"\.(?:find|findOne|updateOne|deleteOne|where)\s*\(\s*(?:req\.(?:body|query|params)|\{\s*\$where)",
         "high", "injection", "CWE-943", A03, "A query object comes straight from the request, so operators like $ne can be injected.",
         "Validate and cast fields (e.g. String(req.body.user)) or use a schema validator."),
    Rule("JS-XSS-001", "DOM XSS via innerHTML", r"\.(?:innerHTML|outerHTML)\s*\+?=", "high", "xss", "CWE-79", A03,
         "Assigning HTML strings to innerHTML executes injected scripts.", "Use textContent, or sanitize with DOMPurify.sanitize()."),
    Rule("JS-XSS-002", "DOM XSS via document.write", r"\bdocument\.write(?:ln)?\s*\(", "medium", "xss", "CWE-79", A03,
         "document.write() inserts raw HTML.", "Create elements with the DOM API and set textContent."),
    Rule("JS-XSS-003", "Reflected XSS in response", r"\bres\.(?:send|write|end)\s*\(.*(?:req\.(?:query|params|body)|`[^`]*<[^`]*\$\{|['\"]<[^'\"]*['\"]\s*\+)",
         "high", "xss", "CWE-79", A03, "Request data is written into an HTML response without escaping.",
         "Render with a templating engine that escapes output, or escape values (e.g. with he.encode)."),
    Rule("JS-XSS-004", "React dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*=", "medium", "xss", "CWE-79", A03,
         "dangerouslySetInnerHTML bypasses React's escaping.", "Render text normally, or sanitize with DOMPurify first."),
    Rule("JS-PATH-001", "Path traversal", r"\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|writeFile|unlink|sendFile)\s*\(", "high",
         "path_ssrf", "CWE-22", "A01:2021 Broken Access Control", "A file path is built from user input.",
         "Use path.basename() or resolve the path and check it stays inside the allowed directory.", requires_input=True),
    Rule("JS-SSRF-001", "Server-side request forgery (SSRF)", r"\b(?:fetch|axios(?:\.(?:get|post|request))?|got|request|http\.get|https\.get)\s*\(",
         "high", "path_ssrf", "CWE-918", "A10:2021 Server-Side Request Forgery", "The server requests a URL controlled by the user.",
         "Allow-list hostnames and block private IP ranges before fetching.", requires_input=True),
    Rule("JS-REDIR-001", "Open redirect", r"\bres\.redirect\s*\(", "medium", "config", "CWE-601", "A01:2021 Broken Access Control",
         "Users can be redirected to an attacker's site.", "Redirect only to relative paths or an allow-list of URLs.", requires_input=True),
    Rule("JS-PROTO-001", "Prototype pollution", r"(?:__proto__|constructor\s*\[\s*['\"]prototype)|\b(?:_\.merge|merge|extend|defaultsDeep)\s*\(\s*[^,]+,\s*req\.",
         "high", "injection", "CWE-1321", A03, "Merging user-controlled objects can modify Object.prototype.",
         "Validate input with a schema and merge only known keys; use Object.create(null) for maps."),
    Rule("JS-CRYPTO-001", "Weak hash algorithm (MD5/SHA-1)", r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", "medium", "crypto", "CWE-327", A02,
         "MD5 and SHA-1 are broken for security use.", "Use bcrypt/argon2 for passwords and sha256 for integrity.", flags=re.I),
    Rule("JS-RAND-001", "Insecure randomness for a secret", r"(?:token|secret|password|otp|nonce|session|key)\w*\s*[:=].*Math\.random\s*\(",
         "medium", "crypto", "CWE-338", A02, "Math.random() is predictable.", "Use crypto.randomBytes(32) or crypto.randomUUID().", flags=re.I),
    Rule("JS-JWT-001", "JWT verification bypass", r"jwt\.(?:decode)\s*\(|algorithms\s*:\s*\[\s*['\"]none['\"]", "high", "config", "CWE-347", A07,
         "jwt.decode() does not verify the signature ('none' algorithm accepts unsigned tokens).",
         "Use jwt.verify(token, key, { algorithms: ['HS256'] })."),
    Rule("JS-TLS-001", "TLS verification disabled", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", "medium",
         "config", "CWE-295", A07, "Certificate validation is turned off.", "Keep rejectUnauthorized enabled; trust your internal CA instead."),
    Rule("JS-CORS-001", "Permissive CORS with credentials", r"origin\s*:\s*(?:true|['\"]\*['\"])", "low", "config", "CWE-942", A05,
         "Any website may call this API.", "Allow-list trusted origins explicitly."),
]

PHP_RULES = [
    Rule("PHP-CODE-001", "Code injection via eval()", r"\beval\s*\(", "critical", "injection", "CWE-95", A03,
         "eval() executes a string as PHP code.", "Remove eval(); use explicit logic or json_decode() for data."),
    Rule("PHP-CMDI-001", "OS command injection", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$", "critical",
         "injection", "CWE-78", A03, "The command runs through the system shell.",
         "Avoid shell calls; if needed wrap every argument with escapeshellarg() and allow-list values."),
    Rule("PHP-SQLI-001", "SQL injection", r"\b(?:mysqli_query|mysql_query|pg_query|sqlite_query)\s*\(|->(?:query|exec)\s*\(\s*(?:\"[^\"]*\$|\"[^\"]*\"\s*\.|'[^']*'\s*\.)",
         "critical", "injection", "CWE-89", A03, "The SQL query includes variables directly.",
         "Use prepared statements: $stmt = $pdo->prepare('... WHERE id = ?'); $stmt->execute([$id]);"),
    Rule("PHP-LFI-001", "File inclusion (LFI/RFI)", r"\b(?:include|require)(?:_once)?\s*\(?\s*[^;]*\$", "critical", "path_ssrf", "CWE-98",
         "A01:2021 Broken Access Control", "A user-controlled path is included and executed as PHP.",
         "Map allowed page names to fixed file paths; never include request data.", requires_input=True),
    Rule("PHP-PATH-001", "Path traversal", r"\b(?:file_get_contents|fopen|readfile|file|unlink|file_put_contents)\s*\(", "high", "path_ssrf",
         "CWE-22", "A01:2021 Broken Access Control", "A file path comes from user input.",
         "Use basename() and check the resolved path with realpath() stays inside the allowed directory.", requires_input=True),
    Rule("PHP-XSS-001", "Reflected cross-site scripting", r"\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)", "high", "xss", "CWE-79", A03,
         "Request data is printed into the page without escaping.", "Escape output: echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8');"),
    Rule("PHP-DESER-001", "Insecure deserialization", r"\bunserialize\s*\(", "high", "deserialization", "CWE-502", A08,
         "unserialize() on untrusted data can trigger object injection.", "Use json_decode(); or pass ['allowed_classes' => false]."),
    Rule("PHP-EXTRACT-001", "Variable overwrite via extract()", r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)", "high", "injection", "CWE-621", A03,
         "extract() turns request parameters into variables, letting users overwrite any variable.", "Read the specific parameters you need."),
    Rule("PHP-CRYPTO-001", "Weak password hashing", r"\b(?:md5|sha1)\s*\(", "medium", "crypto", "CWE-327", A02,
         "md5()/sha1() are broken for security use.", "Use password_hash($password, PASSWORD_DEFAULT) and password_verify()."),
    Rule("PHP-RAND-001", "Insecure randomness", r"\b(?:rand|mt_rand|uniqid)\s*\(", "low", "crypto", "CWE-338", A02,
         "rand()/mt_rand()/uniqid() are predictable.", "Use random_bytes() or random_int()."),
    Rule("PHP-SSRF-001", "Server-side request forgery (SSRF)", r"\b(?:curl_setopt\s*\([^,]+,\s*CURLOPT_URL|curl_init|fsockopen)\s*\(?", "high",
         "path_ssrf", "CWE-918", "A10:2021 Server-Side Request Forgery", "The server requests a URL controlled by the user.",
         "Allow-list hosts and block internal IP ranges.", requires_input=True),
]

JAVA_RULES = [
    Rule("JAVA-CMDI-001", "OS command injection", r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(", "critical", "injection",
         "CWE-78", A03, "A system command is built from strings.", "Pass a fixed command and validated arguments as a String[]; never build one shell string."),
    Rule("JAVA-SQLI-001", "SQL injection", r"\.(?:executeQuery|executeUpdate|execute|addBatch|createQuery|createNativeQuery)\s*\(\s*(?:\"[^\"]*\"\s*\+|[a-zA-Z_]\w*\s*\+)",
         "critical", "injection", "CWE-89", A03, "The SQL query is concatenated from strings.",
         "Use PreparedStatement with ? placeholders and setString()/setInt()."),
    Rule("JAVA-SQLI-002", "SQL built by concatenation", r"\"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"\s*\+", "high", "injection", "CWE-89", A03,
         "A SQL string is concatenated with a variable.", "Use PreparedStatement placeholders.", flags=re.I),
    Rule("JAVA-DESER-001", "Insecure deserialization", r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|XMLDecoder\s*\(", "high", "deserialization",
         "CWE-502", A08, "Java deserialization of untrusted data can execute code (gadget chains).",
         "Avoid native serialization; use JSON, or an ObjectInputFilter allow-list."),
    Rule("JAVA-XXE-001", "XML external entities (XXE)", r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(", "high", "injection",
         "CWE-611", A05, "The XML parser may resolve external entities, exposing local files.",
         'Disable DTDs: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).'),
    Rule("JAVA-XSS-001", "Reflected cross-site scripting", r"getWriter\(\)\.(?:print|println|write)\s*\(.*(?:getParameter|getHeader|getQueryString)", "high",
         "xss", "CWE-79", A03, "Request data is written into the response without encoding.",
         "Encode output with OWASP Java Encoder: Encode.forHtml(value)."),
    Rule("JAVA-PATH-001", "Path traversal", r"new\s+(?:File|FileInputStream|FileReader|FileOutputStream)\s*\(|Paths\.get\s*\(", "high", "path_ssrf",
         "CWE-22", "A01:2021 Broken Access Control", "A file path is built from user input.",
         "Normalize the path and verify it starts with the allowed base directory.", requires_input=True),
    Rule("JAVA-CRYPTO-001", "Weak hash algorithm (MD5/SHA-1)", r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"", "medium", "crypto", "CWE-327", A02,
         "MD5 and SHA-1 are broken for security use.", "Use SHA-256 for integrity and bcrypt/Argon2 for passwords.", flags=re.I),
    Rule("JAVA-CRYPTO-002", "Weak cipher (DES/ECB)", r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|RC4|AES/ECB|AES\")", "high", "crypto", "CWE-327", A02,
         "DES/RC4 are broken and ECB mode leaks patterns.", 'Use Cipher.getInstance("AES/GCM/NoPadding") with a random IV.'),
    Rule("JAVA-RAND-001", "Insecure randomness", r"new\s+Random\s*\(|Math\.random\s*\(", "low", "crypto", "CWE-330", A02,
         "java.util.Random is predictable.", "Use java.security.SecureRandom for tokens and keys."),
    Rule("JAVA-TLS-001", "Trust-all certificate manager", r"X509TrustManager|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier",
         "high", "config", "CWE-295", A07, "Certificate checks are bypassed.", "Use the default TrustManager and HostnameVerifier."),
]

RULES = {"javascript": JS_RULES, "php": PHP_RULES, "java": JAVA_RULES}

SOURCES = {
    "javascript": r"\breq\.(?:query|body|params|cookies|headers|get\s*\()|\blocation\.(?:hash|search|href)|document\.(?:URL|location|referrer|cookie)|window\.name|\bprocess\.argv|\.value\b|URLSearchParams",
    "php": r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\bfile_get_contents\s*\(\s*['\"]php://input|\$argv",
    "java": r"\b(?:request|req)\.get(?:Parameter|Header|QueryString|Cookies|InputStream|Reader)\s*\(|@RequestParam|@PathVariable|@RequestBody|\bargs\s*\[",
}
ASSIGN = {
    "javascript": r"(?:const|let|var)\s+(?:\{\s*([\w\s,]+)\}|([A-Za-z_$][\w$]*))\s*=",
    "php": r"\$([A-Za-z_]\w*)\s*=",
    "java": r"(?:String|int|long|Integer|Object|var)\s+([A-Za-z_]\w*)\s*=",
}
SANITIZERS = {
    "javascript": r"encodeURIComponent|DOMPurify\.sanitize|escape(?:Html)?\(|\bhe\.encode|validator\.|parseInt\(|Number\(|\?\s*[,)]|path\.basename|textContent",
    "php": r"htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|intval\(|\(int\)|filter_var|filter_input|->prepare\(|bindParam|bindValue|basename\(|realpath\(",
    "java": r"PreparedStatement|setString\(|setInt\(|Encode\.for|ESAPI|StringEscapeUtils|Integer\.parseInt|FilenameUtils\.getName|normalize\(\)",
}
SENSITIVE = re.compile(r"(?i)passw|pwd|secret|token|otp|nonce|salt|session|api.?key|credential|\bpin\b")
ROUTE = re.compile(r"\b(?:app|router)\.(?:get|post|put|delete|use)\s*\(|@(?:Get|Post|Put|Request)Mapping|\$_(?:GET|POST|REQUEST)|HttpServletRequest")
MULTILINE_CATEGORIES = {"deserialization"}
# x.innerHTML = "<b>fixed</b>";  — a plain string literal assigned, nothing interpolated
LITERAL_ASSIGN = re.compile(r"=\s*(['\"])(?:(?!\1)[^\\$`]|\\.)*\1\s*;?\s*(?://.*)?$")
LITERAL_ARG = re.compile(r"\(\s*(['\"])(?:(?!\1)[^\\$]|\\.)*\1\s*[,)]")  # f('fixed string') with no $interpolation


def _dynamic(language: str, line: str) -> bool:
    if "${" in line and "`" in line:
        return True
    if language == "php":
        return bool(re.search(r"\"[^\"]*\$\w|\.\s*\$\w|\$\w+\s*\.", line))
    return bool(re.search(r"['\"]\s*\+\s*[A-Za-z_$]|[A-Za-z_$][\w$\]\)]*\s*\+\s*['\"]", line))


def _strip_strings(line: str) -> str:
    return re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", '""', line)


def analyze(code: str, language: str, filename: str = "snippet") -> list[Finding]:
    rules = RULES[language]
    source_re = re.compile(SOURCES[language])
    assign_re = re.compile(ASSIGN[language])
    sanitize_re = re.compile(SANITIZERS[language])
    in_test = _looks_like_test(filename)
    in_route = bool(ROUTE.search(code))
    tainted: dict[str, int] = {}  # variable → line it was assigned from user input
    findings: list[Finding] = []
    in_block_comment = False

    all_lines = code.splitlines()
    for lineno, line in enumerate(all_lines, start=1):
        # Statements often span lines (getInstance("MD5") … digest(password)): look at neighbours for context.
        nearby = "\n".join(all_lines[max(0, lineno - 2):lineno + 2])
        stripped = line.strip()
        # ---- comment tracking (/* ... */, //, # in PHP) ----
        comment = in_block_comment
        if in_block_comment and "*/" in stripped:
            in_block_comment = False
        if stripped.startswith("/*") or stripped.startswith("*"):
            comment = True
            if "*/" not in stripped:
                in_block_comment = True
        if stripped.startswith("//") or (language == "php" and stripped.startswith("#")):
            comment = True

        # ---- light taint: remember variables assigned from user input ----
        # PHP interpolates "$var" inside double quotes, so strings must stay in for the taint check.
        code_part = line if language == "php" else _strip_strings(line)
        has_source = bool(source_re.search(line))
        uses_tainted = next(((v, ln) for v, ln in tainted.items() if re.search(rf"(?<![\w$]){re.escape(v)}(?![\w])", code_part)), None)
        m = assign_re.search(line)
        if m and not comment and (has_source or uses_tainted):
            names = m.group(1) if m.lastindex and m.group(1) else (m.group(m.lastindex) if m.lastindex else "")
            for name in re.split(r"[\s,]+", names or ""):
                name = name.split(":")[0].strip()
                if name:
                    tainted.setdefault(("$" + name) if language == "php" else name, lineno)

        user_input = has_source or uses_tainted is not None
        nearby_input = not comment and bool(source_re.search(nearby))
        for rule in rules:
            if not rule.regex.search(line):
                continue
            # Parser/deserializer setups span lines (newInstance() here, parse(request...) next line).
            rule_input = user_input or ((rule.category in MULTILINE_CATEGORIES or rule.id == "JAVA-XXE-001") and nearby_input)
            if rule.requires_input and not rule_input:
                continue
            source = None
            if has_source:
                source_line, source = lineno, source_re.search(line).group(0)
            elif uses_tainted:
                source = f"variable '{uses_tainted[0]}'"
                source_line = uses_tainted[1]
            else:
                source_line = None
            ev = Evidence(
                tainted=uses_tainted is not None or (has_source and not comment),
                user_input=rule_input,
                dynamic=_dynamic(language, line),
                literal_only=bool(LITERAL_ARG.search(line) or LITERAL_ASSIGN.search(line)) and not rule_input,
                sanitized=bool(sanitize_re.search(line)),
                in_test=in_test,
                in_comment=comment,
                in_route=in_route,
                sensitive_context=rule.category == "crypto" and bool(SENSITIVE.search(nearby)),
                source=source,
                source_line=source_line,
            )
            message = rule.message
            if source and not comment:
                message += f" User input from {source}" + (f" (line {source_line})" if source_line else "") + " is used here."
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, severity=rule.severity, category=rule.category, cwe=rule.cwe,
                owasp=rule.owasp, line=lineno, column=(rule.regex.search(line).start() + 1), message=message, fix=rule.fix,
                language=language, snippet=stripped[:240], evidence=ev,
            ))
    return findings
