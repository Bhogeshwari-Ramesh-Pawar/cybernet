"""Hard-coded secret detection for any language.

Provider-specific patterns (AWS, GitHub, Stripe, ...) are high-confidence. Generic
"password = '...'" assignments are scored by Shannon entropy and placeholder detection,
so "changeme" or "your-api-key-here" rank far below a real random key.
Matched values are always masked in the output.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Evidence, Finding
from .python_ast import _looks_like_test

A07 = "A07:2021 Identification and Authentication Failures"
FIX = "Remove the secret from code, rotate it now (assume it is leaked), and load it from an environment variable or a secrets manager."

PROVIDERS = [
    ("SEC-AWS-001", "AWS access key ID", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", "critical"),
    ("SEC-AWS-002", "AWS secret access key", r"(?i)aws.{0,20}?(?:secret|key).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]", "critical"),
    ("SEC-GH-001", "GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", "critical"),
    ("SEC-SLACK-001", "Slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", "high"),
    ("SEC-STRIPE-001", "Stripe live secret key", r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b", "critical"),
    ("SEC-GOOGLE-001", "Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "high"),
    ("SEC-KEY-001", "Private key", r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)", "critical"),
    ("SEC-JWT-001", "JSON Web Token", r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b", "medium"),
    ("SEC-DBURL-001", "Credentials in connection URL", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:/\s'\"]+:([^@\s'\"]{3,})@", "high"),
]
GENERIC = re.compile(
    r"(?i)\b([\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|token|client[_\-]?secret|private[_\-]?key)[\w\-]*)"
    r"[\"']?\s*(?:=|:|=>|:=)\s*[\"']([^\"'\s]{4,})[\"']"
)
PLACEHOLDER = re.compile(
    r"(?i)^(?:changeme|change[_\-]?me|password\d*|secret|test\w*|dummy|example\w*|sample|xxx+|\*+|null|none|todo|fixme|placeholder|"
    r"your[_\-].*|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|.*example\.com.*|insert.*|redacted|replace.*|admin|default|foo|bar|abc\d*|123\d*|pass)$"
)
ENV_READ = re.compile(r"(?i)os\.environ|getenv|process\.env|System\.getenv|\$_ENV|env\(|config\[|settings\.")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 4)} ({len(value)} chars)"


def analyze(code: str, language: str, filename: str = "snippet") -> list[Finding]:
    in_test = _looks_like_test(filename)
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        comment = stripped.startswith(("#", "//", "/*", "*", "--"))
        hit_on_line = False
        for rule_id, title, pattern, severity in PROVIDERS:
            for m in re.finditer(pattern, line):
                value = m.group(1)
                ev = Evidence(in_test=in_test, in_comment=comment, entropy=round(entropy(value), 2),
                              placeholder=bool(PLACEHOLDER.match(value)) or "EXAMPLE" in value.upper(), literal_only=True)
                findings.append(_finding(rule_id, title, severity, lineno, m.start(1) + 1, language,
                                         f"{title} found in source code: {mask(value)}.",
                                         line.replace(value, mask(value)).strip()[:240], ev))
                hit_on_line = True
        if hit_on_line or ENV_READ.search(line):
            continue
        for m in GENERIC.finditer(line):
            name, value = m.group(1), m.group(2)
            if PLACEHOLDER.match(value) or value.lower() in name.lower():
                placeholder = True
            else:
                placeholder = False
            if re.fullmatch(r"[A-Za-z_][\w.]*\(\)?|true|false", value, re.I):  # a variable/function name, not a secret
                continue
            ent = entropy(value)
            severity = "high" if ent >= 3.5 and len(value) >= 12 and not placeholder else "medium" if not placeholder else "low"
            ev = Evidence(in_test=in_test, in_comment=comment, entropy=round(ent, 2), placeholder=placeholder, literal_only=True,
                          sensitive_context=True)
            findings.append(_finding("SEC-GEN-001", "Hard-coded credential", severity, lineno, m.start(2) + 1, language,
                                     f"'{name}' is assigned a hard-coded value: {mask(value)}.",
                                     line.replace(value, mask(value)).strip()[:240], ev))
    return findings


def _finding(rule_id, title, severity, line, column, language, message, snippet, ev) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category="secret", cwe="CWE-798", owasp=A07,
                   line=line, column=column, message=message, fix=FIX, language=language, snippet=snippet, evidence=ev)
