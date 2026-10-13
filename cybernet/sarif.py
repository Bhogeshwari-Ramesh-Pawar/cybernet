"""SARIF 2.1.0 export, the standard format for static-analysis results.

GitHub Code Scanning, Azure DevOps and the VS Code SARIF Viewer all read it.
"""

from __future__ import annotations

from typing import Any

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_sarif(result: dict[str, Any], version: str) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in result["findings"]:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"],
            "name": f["title"],
            "shortDescription": {"text": f["title"]},
            "help": {"text": f["fix"]},
            "properties": {"tags": ["security", f["cwe"], f["owasp"]], "security-severity": SCORE[f["severity"]]},
        })
        results.append({
            "ruleId": f["rule_id"],
            "level": LEVEL[f["severity"]],
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": result["filename"]},
                "region": {"startLine": f["line"], "startColumn": f["column"], "snippet": {"text": f["snippet"]}},
            }}],
            "properties": {"severity": f["severity"], "confidence": f["confidence"], "priority": f["priority"],
                           "cwe": f["cwe"], "owasp": f["owasp"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CyberNet", "version": version, "informationUri": "https://github.com/Bhogeshwari-Ramesh-Pawar/cybernet",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
