"""Turn a finding's evidence into the numeric feature vector the model is trained on."""

from __future__ import annotations

from ..models import CATEGORIES, SEVERITY_WEIGHT, Finding

# (name, label shown to the user when it influences the score)
FEATURES: list[tuple[str, str]] = [
    ("severity", "rule severity"),
    ("tainted", "user input reaches the dangerous call"),
    ("user_input", "user input on the same line"),
    ("dynamic", "argument built at runtime"),
    ("literal_only", "only fixed values are used"),
    ("sanitized", "sanitizer or parameterization present"),
    ("in_test", "located in a test file"),  # code issues only: a real key leaked in a test is still leaked
    ("in_comment", "inside a comment"),
    ("in_route", "inside a web request handler"),
    ("sensitive_context", "security-sensitive context"),
    ("high_entropy", "random-looking secret value"),
    ("placeholder", "placeholder value"),
] + [(f"cat_{c}", f"{c.replace('_', '/')} issue") for c in CATEGORIES]

NAMES = [name for name, _ in FEATURES]
LABELS = dict(FEATURES)


def vector(f: Finding) -> list[float]:
    e = f.evidence
    values = {
        "severity": SEVERITY_WEIGHT.get(f.severity, 0.5),
        "tainted": float(e.tainted),
        "user_input": float(e.user_input),
        "dynamic": float(e.dynamic),
        "literal_only": float(e.literal_only),
        "sanitized": float(e.sanitized),
        "in_test": float(e.in_test and f.category != "secret"),
        "in_comment": float(e.in_comment),
        "in_route": float(e.in_route),
        "sensitive_context": float(e.sensitive_context),
        # 4.5 bits/char is typical for random base64/hex keys; English words sit near 2.5–3
        "high_entropy": max(0.0, min(1.0, (e.entropy - 2.5) / 2.0)) if f.category == "secret" else 0.0,
        "placeholder": float(e.placeholder),
    }
    for c in CATEGORIES:
        values[f"cat_{c}"] = float(f.category == c)
    return [values[n] for n in NAMES]
