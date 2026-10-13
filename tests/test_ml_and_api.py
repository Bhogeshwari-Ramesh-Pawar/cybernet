import json

from fastapi.testclient import TestClient

from cybernet.main import app
from cybernet.ml.corpus import build
from cybernet.ml.features import NAMES, vector
from cybernet.ml.model import LogisticRegression, sigmoid
from cybernet.models import Evidence, Finding
from cybernet.samples import SAMPLES
from cybernet.scanner import raw_findings, scan

client = TestClient(app)


def finding(**ev):
    return Finding(rule_id="X", title="t", severity="critical", category="injection", cwe="CWE-78", owasp="A03", line=1,
                   column=1, message="m", fix="f", language="python", evidence=Evidence(**ev))


# ---------- model ----------

def test_logistic_regression_learns_a_simple_rule():
    X = [[1.0, 0.0], [1.0, 1.0], [0.0, 0.0], [0.0, 1.0]] * 10
    y = [1, 1, 0, 0] * 10
    import cybernet.ml.model as mm
    original = mm.NAMES
    mm.NAMES = ["a", "b"]
    try:
        m = LogisticRegression([0.0, 0.0]).fit(X, y, epochs=800)
        assert m.predict_proba([1.0, 0.0]) > 0.8 and m.predict_proba([0.0, 1.0]) < 0.2
    finally:
        mm.NAMES = original


def test_sigmoid_is_stable_for_large_inputs():
    assert sigmoid(1000) == 1.0 and sigmoid(-1000) == 0.0


def test_every_corpus_template_produces_findings():
    for language, filename, code, _, idx in build(variants=1):
        assert raw_findings(code, language, filename), f"template {idx} produced nothing"


def test_trained_model_ranks_evidence_sensibly():
    m = LogisticRegression.load()
    real = m.predict_proba(vector(finding(tainted=True, user_input=True, dynamic=True, in_route=True)))
    literal = m.predict_proba(vector(finding(literal_only=True)))
    in_test = m.predict_proba(vector(finding(tainted=True, user_input=True, in_test=True)))
    sanitized = m.predict_proba(vector(finding(tainted=False, sanitized=True, dynamic=True)))
    assert real > 0.75 and literal < 0.5 and in_test < real and sanitized < real


def test_model_metrics_are_recorded_and_honest():
    m = LogisticRegression.load()
    cv = m.meta["cross_validation"]
    assert cv["accuracy"] >= 0.8 and cv["f1"] >= 0.8
    assert m.meta["samples"] > 500 and len(m.weights) == len(NAMES)


def test_explanations_name_the_driving_evidence():
    m = LogisticRegression.load()
    reasons = m.explain(vector(finding(tainted=True, user_input=True, in_test=True)))
    labels = {r["feature"] for r in reasons}
    assert "in_test" in labels and any(r["direction"] == "down" for r in reasons)


# ---------- end to end ----------

def test_samples_rank_real_issues_above_look_alikes():
    py = scan(SAMPLES["python"])
    top = py["findings"][0]
    assert top["evidence"]["tainted"] and top["severity"] == "critical"
    by_snippet = {f["snippet"]: f for f in py["findings"]}
    cmd = next(f for s, f in by_snippet.items() if 'os.system("ping' in s)
    fixed = next(f for s, f in by_snippet.items() if "rm -rf /tmp/build-cache" in s)
    placeholder = next(f for s, f in by_snippet.items() if "ADMIN_PASSWORD" in s)
    assert cmd["priority"] > fixed["priority"] and cmd["priority"] > placeholder["priority"]


def test_every_sample_scans_and_detects_its_language():
    for lang, code in SAMPLES.items():
        r = scan(code)
        assert r["language"] == lang and r["summary"]["likely_real"] >= 3


def test_api_scan_and_validation():
    r = client.post("/api/scan", json={"code": "import os\nos.system(input())\n"})
    assert r.status_code == 200
    f = r.json()["findings"][0]
    assert f["rule_id"] == "PY-CMDI-001" and f["evidence"]["tainted"] and f["confidence"] > 0.5
    assert client.post("/api/scan", json={"code": "   "}).status_code == 400
    assert client.post("/api/scan", json={"code": "x", "language": "cobol"}).status_code == 422
    assert client.post("/api/scan", json={"code": "def broken(:\n", "language": "python"}).status_code == 400


def test_sarif_export_is_valid_shape():
    r = client.post("/api/sarif", json={"code": SAMPLES["javascript"], "filename": "server.js"})
    data = json.loads(r.text)
    assert data["version"] == "2.1.0" and r.headers["content-disposition"].startswith("attachment")
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "CyberNet" and run["results"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "server.js"


def test_meta_and_samples_endpoints():
    meta = client.get("/api/meta").json()
    assert meta["rules"] > 60 and meta["model"]["cross_validation"]["accuracy"] > 0.8 and meta["model"]["weights"]
    assert set(client.get("/api/samples").json()) == {"python", "javascript", "php", "java"}


def test_secret_values_never_leave_the_server_unmasked():
    key = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    body = client.post("/api/scan", json={"code": f"const k = '{key}';\n"}).text
    assert key not in body


def test_dashboard_served():
    assert "CyberNet" in client.get("/").text
