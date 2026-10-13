"""Run the analyzers on a piece of code, then rank the findings with the ML model."""

from __future__ import annotations

import re
import time
from functools import lru_cache
from typing import Any

from .analyzers import patterns, python_ast, secrets
from .ml.features import vector
from .ml.model import MODEL_PATH, LogisticRegression
from .models import SEVERITY_WEIGHT, Finding

LANGUAGES = {"python": "Python", "javascript": "JavaScript / Node.js", "php": "PHP", "java": "Java"}
MAX_CODE = 200_000  # characters

_HINTS = {
    "php": [r"<\?php", r"\$_(?:GET|POST|REQUEST)", r"\$\w+\s*=", r"\bfunction\s+\w+\s*\(\s*\$", r"->\w+\("],
    "java": [r"\bpublic\s+(?:static\s+)?(?:class|void|String|int)\b", r"\bimport\s+java\.", r"System\.out\.", r"@(?:Override|RestController|GetMapping)",
             r"\bnew\s+[A-Z]\w*\(", r";\s*$"],
    "javascript": [r"\b(?:const|let|var)\s+\w+\s*=", r"\brequire\(\s*['\"]", r"=>", r"\bfunction\s*\w*\s*\(", r"\bdocument\.", r"\bconsole\.log",
                   r"\bmodule\.exports|\bexport\s+(?:default|const|function)", r"\bawait\b"],
    "python": [r"^\s*def\s+\w+\s*\(.*\)\s*:", r"^\s*import\s+\w+|^\s*from\s+\w+(?:\.\w+)*\s+import", r"^\s*(?:if|for|while|with|elif|else|try|except)\b.*:\s*$",
               r"\bprint\(", r"\bself\b", r"^\s*@\w+", r"\bNone\b|\bTrue\b|\bFalse\b"],
}


def detect_language(code: str) -> str:
    """Guess the language from characteristic syntax (the user can always override it)."""
    if re.search(r"<\?php", code):
        return "php"
    scores = {lang: sum(len(re.findall(p, code, re.M)) for p in pats) for lang, pats in _HINTS.items()}
    return max(scores, key=scores.get) if any(scores.values()) else "python"


@lru_cache(maxsize=1)
def model() -> LogisticRegression | None:
    return LogisticRegression.load() if MODEL_PATH.exists() else None


def raw_findings(code: str, language: str, filename: str) -> list[Finding]:
    """All analyzer findings, before ML ranking (also used to build the training corpus)."""
    if language == "python":
        found = python_ast.analyze(code, filename)
    elif language in patterns.RULES:
        found = patterns.analyze(code, language, filename)
    else:
        raise ValueError(f"unsupported language '{language}'")
    found += secrets.analyze(code, language, filename)
    # One report per weakness (CWE) per line: several rules can describe the same construct.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique: dict[tuple, Finding] = {}
    for f in sorted(found, key=lambda f: rank[f.severity]):
        unique.setdefault((f.cwe, f.line), f)
    return sorted(unique.values(), key=lambda f: (f.line, f.column))


def prioritize(findings: list[Finding]) -> list[Finding]:
    m = model()
    for f in findings:
        if m is None:  # untrained fallback: severity only
            f.confidence = 0.5
        else:
            x = vector(f)
            f.confidence = round(m.predict_proba(x), 3)
            f.reasons = m.explain(x)
        # Priority = how likely it is real (ML) × how bad it would be (severity).
        # Confidence leads, so a commented-out "critical" never outranks a real medium issue.
        f.priority = round(100 * f.confidence * (0.6 + 0.4 * SEVERITY_WEIGHT.get(f.severity, 0.5)))
    return sorted(findings, key=lambda f: (-f.priority, f.line))


def grade(findings: list[Finding]) -> tuple[int, str]:
    """0–100 security score: each likely-real finding costs points by severity."""
    penalty = sum({"critical": 30, "high": 18, "medium": 8, "low": 3}[f.severity] * f.confidence for f in findings)
    score = max(0, round(100 - penalty))
    letter = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, letter


def scan(code: str, language: str = "auto", filename: str | None = None) -> dict[str, Any]:
    if not code.strip():
        raise ValueError("Paste some code to scan.")
    if len(code) > MAX_CODE:
        raise ValueError(f"Code is too large ({len(code):,} characters, max {MAX_CODE:,}).")
    started = time.perf_counter()
    detected = detect_language(code)
    lang = detected if language in (None, "", "auto") else language
    if lang not in LANGUAGES:
        raise ValueError(f"language must be one of {list(LANGUAGES)} or auto")
    filename = filename or {"python": "main.py", "javascript": "app.js", "php": "index.php", "java": "Main.java"}[lang]

    findings = prioritize(raw_findings(code, lang, filename))
    likely = [f for f in findings if f.confidence >= 0.5]
    score, letter = grade(findings)
    m = model()
    return {
        "language": lang,
        "detected_language": detected,
        "filename": filename,
        "lines": code.count("\n") + 1,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "score": score,
        "grade": letter,
        "summary": {
            "total": len(findings),
            "likely_real": len(likely),
            "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low")},
        },
        "findings": [f.to_dict() for f in findings],
        "model": ({"type": "Logistic regression", **{k: v for k, v in m.meta.items() if k != "saved_at"}} if m else None),
    }
