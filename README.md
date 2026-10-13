# CyberNet: AI-Prioritized Static Code Security (SAST)

Paste code and CyberNet finds the vulnerabilities and leaked secrets in it. A trained ML model then
ranks every finding by **how likely it is to be real and exploitable**, so developers fix the dangerous
issues first instead of wading through false positives.

| | |
|---|---|
| **Python** | AST analysis with **taint tracking**: follows user input (`request.args`, `input()`, route parameters, `sys.argv`) through variables, f-strings, concatenation and `.format()` into dangerous sinks; recognizes sanitizers (`shlex.quote`, `html.escape`, `int()`, `secure_filename`) |
| **JavaScript / Node.js, PHP, Java** | Rule engine with light taint tracking (variables assigned from `req.query`, `$_GET`, `request.getParameter`), comment detection, sanitizer and prepared-statement detection |
| **Secrets (any language)** | AWS, GitHub, Stripe, Slack and Google keys, private keys, JWTs, credentials in connection URLs, hard-coded passwords, scored by entropy with placeholder detection. Values are always masked |
| **AI prioritization** | Logistic regression trained on a labelled corpus, explaining each prediction |
| **Output** | Severity, CWE, OWASP Top 10 2021, data-flow trace, fix advice; export to **SARIF 2.1.0** (GitHub Code Scanning, VS Code), JSON or Markdown |

## What it detects

SQL / NoSQL injection, OS command injection, code injection (`eval`, `exec`, `new Function`), server-side
template injection, reflected and DOM XSS, path traversal, file inclusion, SSRF, open redirect, insecure
deserialization (`pickle`, `yaml.load`, `unserialize`, `ObjectInputStream`), XXE, prototype pollution, weak
hashing and ciphers (MD5, SHA-1, DES, ECB), insecure randomness, disabled TLS verification, JWT signature
bypass, debug mode, permissive CORS and hard-coded secrets: **70 rules** in total.

## How the AI prioritization works

Rules alone are noisy: `os.system("ls -la")` and `os.system("ping " + user_input)` match the same rule, but
only one is exploitable. For every finding the analyzers record **evidence**, and the model turns it into a
probability:

| Evidence (feature) | Learned effect |
|---|---|
| user input provably reaches the dangerous call (taint) | ↑ |
| user input on the same line / inside a web route | ↑ |
| security-sensitive context (MD5 of a *password*, random *token*) | ↑ |
| random-looking secret value (Shannon entropy) | ↑ |
| located in a test file (code issues; a leaked key in a test is still leaked) | ↓ |
| sanitizer or parameterized query present | ↓ |
| only fixed literal values / inside a comment / placeholder secret | ↓ |

**Model:** logistic regression, implemented from scratch (`cybernet/ml/model.py`), with class weighting and L2
regularization. Every prediction is explained by its largest feature contributions (wᵢ·xᵢ), shown as
▲/▼ reasons on each finding.

**Data:** `cybernet/ml/corpus.py` defines 87 labelled code patterns across the four languages (real
vulnerabilities and look-alike false positives), expanded with randomized identifiers, file names, test-file
and commented-out variants. Features are extracted by running the real scanner, so training and scanning
share one code path.

**Evaluation:** 5-fold **group** cross-validation, where all variants of a pattern stay in one fold, so the model
is always scored on patterns it never saw:

| Accuracy | Precision | Recall | F1 |
|---|---|---|---|
| 88.8% | 93.6% | 86.4% | 0.90 |

Priority = confidence × severity weight, so a commented-out "critical" never outranks a real medium issue.

> Honest scope: the corpus is hand-labelled synthetic code, not a large real-world dataset, so treat the scores
> as a measure of how well the model generalizes across *patterns*, not as a production benchmark. Python gets
> intra-procedural data-flow analysis; JS, PHP and Java use rules with lighter, line-based taint tracking.

Retrain after changing rules or the corpus:

```powershell
.venv\Scripts\python -m cybernet.ml.train
```

## Run it (Windows)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn cybernet.main:app --port 8001
```

Open http://localhost:8001, pick an example or paste code, and press **Scan** (Ctrl+Enter).

Docker:

```bash
docker build -t cybernet .
docker run -p 8001:8001 cybernet
```

## API

| Method | Path | Body / result |
|---|---|---|
| POST | `/api/scan` | `{"code": "...", "language": "auto\|python\|javascript\|php\|java", "filename": "app.py"}` → findings, score, grade |
| POST | `/api/sarif` | same body → SARIF 2.1.0 file |
| GET | `/api/meta` | languages, rule count, model metrics and weights |
| GET | `/api/samples` | example vulnerable programs |

Interactive docs: http://localhost:8001/docs

## Tests

```powershell
.venv\Scripts\python -m pytest
```

41 tests cover taint propagation, sanitizers, aliases, scoping, every language's rules, secret masking and
entropy, the model (training, stability, sensible ranking, recorded metrics, explanations), SARIF output and
the API.

## Project structure

```
cybernet/
  analyzers/python_ast.py   Python AST taint analysis
  analyzers/patterns.py     JavaScript, PHP and Java rules
  analyzers/secrets.py      secret detection (all languages)
  ml/features.py            evidence → feature vector
  ml/model.py               logistic regression + explanations
  ml/corpus.py              labelled training patterns
  ml/train.py               training + group cross-validation
  ml/model.json             trained weights and metrics
  scanner.py                language detection, orchestration, ranking, score
  sarif.py                  SARIF 2.1.0 export
  main.py                   FastAPI app
  static/                   web UI (CodeMirror editor)
tests/
```

## Note on antivirus

Security tools contain examples of vulnerable code, and antivirus products can flag some of them as malware
(PHP web-shell look-alikes in particular). This project deliberately leaves those patterns out of its training
data and examples, so it can be cloned on a normal developer machine.
