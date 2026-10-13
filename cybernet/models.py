"""Finding model shared by every analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
CATEGORIES = ("injection", "xss", "deserialization", "path_ssrf", "crypto", "config", "secret")


@dataclass
class Evidence:
    """Facts about a finding. They explain it to the user and are the ML model's features."""

    tainted: bool = False         # user input provably flows into the sink (data-flow analysis)
    user_input: bool = False      # user input appears on the same line (weaker signal)
    dynamic: bool = False         # the dangerous argument is built at runtime (concat, f-string, format)
    literal_only: bool = False    # the dangerous argument is a fixed string
    sanitized: bool = False       # a sanitizer / parameterization was seen on the path
    in_test: bool = False         # file looks like a test
    in_comment: bool = False      # the match is inside a comment
    in_route: bool = False        # inside a web request handler
    sensitive_context: bool = False  # e.g. a weak hash applied to something named "password"
    entropy: float = 0.0          # secrets: Shannon entropy of the value
    placeholder: bool = False     # secrets: value looks like "changeme" / "your-key-here"
    source: str | None = None     # where the user input came from, e.g. request.args
    source_line: int | None = None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    cwe: str
    owasp: str
    line: int
    column: int
    message: str
    fix: str
    language: str
    snippet: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    # Filled in by the ML prioritizer
    confidence: float = 0.0
    priority: int = 0
    reasons: list[dict[str, Any]] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.rule_id, self.line)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
