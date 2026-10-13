// CyberNet front end. Findings echo user-pasted code, so everything is rendered with
// textContent / DOM nodes — never innerHTML.

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function h(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (k === "style") n.style.cssText = v;
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of [].concat(children)) if (c != null && c !== "" && c !== false) n.append(c);
  return n;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2400);
}

const MODES = { python: "python", javascript: "javascript", php: "application/x-httpd-php", java: "text/x-java" };
const SEVERITIES = ["critical", "high", "medium", "low"];
const STORAGE_KEY = "cybernet:draft";

// ---------- editor ----------
const editor = CodeMirror($("#editor"), {
  lineNumbers: true, mode: "python", indentUnit: 4, tabSize: 4, styleActiveLine: true, lineWrapping: false,
  gutters: ["gutter-marks", "CodeMirror-linenumbers"], placeholder: "Paste code here…",
  extraKeys: { "Ctrl-Enter": () => scan(), "Cmd-Enter": () => scan() },
});
try {
  const draft = localStorage.getItem(STORAGE_KEY);
  if (draft) editor.setValue(draft);
} catch {}
editor.on("change", () => {
  try { localStorage.setItem(STORAGE_KEY, editor.getValue().slice(0, 100000)); } catch {}
  updateInfo();
});
function updateInfo() {
  $("#editor-info").textContent = `${editor.lineCount()} lines`;
  $("#editor-title").textContent = $("#filename").value.trim() || "untitled";
}
updateInfo();
$("#filename").addEventListener("input", updateInfo);

function setMode(lang) {
  if (MODES[lang]) editor.setOption("mode", MODES[lang]);
}
$("#language").addEventListener("change", (e) => e.target.value !== "auto" && setMode(e.target.value));

// ---------- model info ----------
let meta = null;
(async () => {
  try {
    meta = await (await fetch("/api/meta")).json();
    const cv = meta.model?.cross_validation;
    $("#model-text").textContent = cv
      ? `ML ranking · ${(cv.accuracy * 100).toFixed(1)}% accuracy on unseen code · ${meta.rules} rules`
      : `${meta.rules} rules · ML model not trained`;
  } catch {
    $("#model-text").textContent = "Offline";
  }
})();

$("#model-badge").addEventListener("click", () => {
  const m = meta?.model;
  const body = $("#model-body");
  if (!m) { body.replaceChildren(h("p", {}, "The model has not been trained yet: run python -m cybernet.ml.train")); $("#model-dialog").showModal(); return; }
  const cv = m.cross_validation;
  const max = Math.max(...m.weights.map((w) => Math.abs(w.weight)));
  body.replaceChildren(
    h("p", {}, ["The analyzers find suspicious code. Then a ", h("b", {}, "logistic regression model"),
      " estimates how likely each finding is to be real and exploitable, from evidence such as whether user input actually reaches the dangerous call, whether a sanitizer is used, or whether the code sits in a test or a comment."]),
    h("h3", {}, "How well it ranks code it has never seen"),
    h("div", { class: "metrics" }, [["Accuracy", cv.accuracy], ["Precision", cv.precision], ["Recall", cv.recall], ["F1", cv.f1]].map(([k, v]) =>
      h("div", { class: "metric" }, [h("b", {}, k === "F1" ? v.toFixed(2) : `${Math.round(v * 100)}%`), h("span", {}, k)]))),
    h("p", { class: "muted" }, `5-fold group cross-validation over ${m.templates} labelled code patterns (${m.samples} findings): each fold is tested only on patterns the model never trained on.`),
    h("h3", {}, "What it learned (weights)"),
    h("div", { class: "weights" }, m.weights.slice(0, 12).flatMap((w) => {
      const pct = Math.abs(w.weight) / max * 50;
      const color = w.weight > 0 ? "var(--critical)" : "var(--low)";
      const pos = w.weight > 0 ? `left:50%;width:${pct}%` : `right:50%;width:${pct}%`;
      return [h("span", {}, w.label), h("div", { class: "bar" }, h("i", { style: `${pos};background:${color}` })), h("code", {}, (w.weight > 0 ? "+" : "") + w.weight.toFixed(2))];
    })),
    h("p", { class: "muted" }, "Red pushes a finding up (more likely real), green pushes it down. Priority = confidence × severity."),
  );
  $("#model-dialog").showModal();
});
document.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) e.target.closest("dialog").close(); });

// ---------- examples ----------
let samples = null;
$("#example").addEventListener("change", async (e) => {
  const lang = e.target.value;
  if (!lang) return;
  samples = samples || (await (await fetch("/api/samples")).json());
  editor.setValue(samples[lang]);
  $("#language").value = lang;
  $("#filename").value = { python: "app.py", javascript: "server.js", php: "shop.php", java: "AccountServlet.java" }[lang];
  setMode(lang);
  updateInfo();
  e.target.value = "";
  scan();
});
$("#clear").addEventListener("click", () => {
  editor.setValue("");
  clearMarks();
  $("#results").hidden = true;
  $("#error").hidden = true;
  $("#empty").hidden = false;
  editor.focus();
});

// ---------- scanning ----------
let last = null;
let show = "likely";

function request() {
  return { code: editor.getValue(), language: $("#language").value, filename: $("#filename").value.trim() || null };
}

async function scan() {
  const btn = $("#scan");
  btn.disabled = true;
  btn.firstChild.textContent = "Scanning… ";
  $("#error").hidden = true;
  try {
    const res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request()) });
    const data = await res.json();
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The scan failed.");
    last = data;
    last.autoDetected = $("#language").value === "auto";
    if (last.autoDetected) setMode(data.language);
    render();
  } catch (err) {
    $("#empty").hidden = true;
    $("#results").hidden = true;
    $("#error").hidden = false;
    $("#error").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.firstChild.textContent = "Scan code ";
  }
}
$("#scan").addEventListener("click", scan);

$$(".seg button").forEach((b) => b.addEventListener("click", () => {
  show = b.dataset.show;
  $$(".seg button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
  renderFindings();
}));

const VERDICTS = { A: "Looks clean", B: "Minor issues", C: "Needs attention", D: "Serious risks", F: "Critical risks found" };

function render() {
  const d = last;
  $("#empty").hidden = true;
  $("#results").hidden = false;
  $("#grade").textContent = d.grade;
  $("#score").textContent = `${d.score}/100`;
  const ring = $("#ring");
  ring.style.strokeDashoffset = String(314.16 * (1 - d.score / 100));
  ring.style.stroke = d.score >= 75 ? "var(--low)" : d.score >= 40 ? "var(--medium)" : "var(--accent)";
  $("#verdict").textContent = d.summary.total ? VERDICTS[d.grade] : "No issues found";
  const langName = { python: "Python", javascript: "JavaScript", php: "PHP", java: "Java" }[d.language];
  $("#score-meta").textContent = `${d.summary.likely_real} likely real of ${d.summary.total} findings · ${langName}` +
    `${d.autoDetected ? " (auto-detected)" : ""} · ${d.lines} lines · ${d.duration_ms} ms`;
  $("#sev-row").replaceChildren(...SEVERITIES.map((s) => {
    const n = d.summary.by_severity[s];
    return h("span", { class: `sev ${s} ${n ? "" : "zero"}` }, `${n} ${s}`);
  }));
  markEditor();
  renderFindings();
}

function renderFindings() {
  const list = last.findings.filter((f) => show === "all" || f.confidence >= 0.5);
  const ol = $("#findings");
  if (!list.length) {
    ol.replaceChildren(h("li", { class: "none" }, last.findings.length
      ? `No likely-real issues. ${last.findings.length} low-confidence finding(s) hidden — switch to "All findings" to review them.`
      : "No vulnerabilities or secrets found in this code."));
    return;
  }
  ol.replaceChildren(...list.map((f, i) => findingCard(f, i)));
}

function findingCard(f) {
  const e = f.evidence;
  const flow = e.tainted && e.source ? h("div", { class: "flow" }, [
    h("span", {}, `${e.source}${e.source_line ? ` · line ${e.source_line}` : ""}`), h("i", {}, "→"), h("span", {}, `line ${f.line}`),
    h("span", { class: "muted", style: "border:0;background:none" }, "user input reaches the sink"),
  ]) : "";
  const card = h("li", { class: `finding ${f.severity} ${f.confidence < 0.5 ? "dim" : ""}`, tabindex: "0", "data-line": f.line,
    on: { click: () => focusLine(f.line, card), keydown: (ev) => ev.key === "Enter" && focusLine(f.line, card) } }, [
    h("div", { class: "f-top" }, [h("h3", { class: "f-title" }, f.title), h("span", { class: "f-prio", title: "Priority = confidence × severity" }, `P${f.priority}`)]),
    h("div", { class: "f-meta" }, [h("b", {}, f.severity), h("span", {}, `line ${f.line}`), h("span", {}, f.cwe), h("span", {}, f.owasp), h("span", {}, f.rule_id)]),
    h("p", { class: "f-msg" }, f.message),
    flow,
    f.snippet ? h("pre", { class: "snippet" }, f.snippet) : "",
    h("div", { class: "ai" }, [h("span", { class: "lbl" }, "AI confidence"), h("div", { class: "meter" }, h("i", { style: `width:${Math.round(f.confidence * 100)}%` })),
      h("b", {}, `${Math.round(f.confidence * 100)}%`)]),
    f.reasons.length ? h("div", { class: "reasons" }, f.reasons.map((r) => h("span", { class: `reason ${r.direction}` }, r.label))) : "",
    h("details", { class: "fix" }, [h("summary", {}, "How to fix"), h("p", {}, f.fix)]),
  ]);
  return card;
}

// ---------- editor markers ----------
let marked = [];
function clearMarks() {
  editor.clearGutter("gutter-marks");
  for (const l of marked) editor.removeLineClass(l, "background", "line-flag");
  marked = [];
}
function markEditor() {
  clearMarks();
  const worst = {};
  for (const f of last.findings) {
    const rank = SEVERITIES.indexOf(f.severity);
    if (!(f.line in worst) || rank < SEVERITIES.indexOf(worst[f.line].severity)) worst[f.line] = f;
  }
  for (const [line, f] of Object.entries(worst)) {
    const idx = Number(line) - 1;
    if (idx >= editor.lineCount()) continue;
    const marker = h("div", { class: `mark ${f.severity}`, title: `${f.title} (${f.severity})` });
    marker.addEventListener("click", () => {
      const card = $(`.finding[data-line="${line}"]`);
      card?.scrollIntoView({ behavior: "smooth", block: "center" });
      focusLine(Number(line), card);
    });
    editor.setGutterMarker(idx, "gutter-marks", marker);
    if (f.confidence >= 0.5) {
      editor.addLineClass(idx, "background", "line-flag");
      marked.push(idx);
    }
  }
}
function focusLine(line, card) {
  $$(".finding.active").forEach((c) => c.classList.remove("active"));
  card?.classList.add("active");
  const idx = line - 1;
  editor.scrollIntoView({ line: idx, ch: 0 }, 120);
  editor.setCursor({ line: idx, ch: 0 });
  editor.addLineClass(idx, "background", "line-focus");
  setTimeout(() => editor.removeLineClass(idx, "background", "line-focus"), 1400);
}

// ---------- exports ----------
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("#export-json").addEventListener("click", () => last && download("cybernet-report.json", JSON.stringify(last, null, 2), "application/json"));
$("#export-sarif").addEventListener("click", async () => {
  const res = await fetch("/api/sarif", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request()) });
  if (!res.ok) return toast("Export failed");
  download("cybernet.sarif", await res.text(), "application/sarif+json");
});
$("#copy-md").addEventListener("click", async () => {
  if (!last) return;
  const lines = [`# CyberNet report: ${last.filename}`, "", `Score **${last.score}/100 (${last.grade})** · ${last.summary.likely_real} likely real of ${last.summary.total} findings`, ""];
  for (const f of last.findings) {
    lines.push(`- **[${f.severity.toUpperCase()}] ${f.title}** (line ${f.line}, ${f.cwe}, AI confidence ${Math.round(f.confidence * 100)}%)`);
    lines.push(`  - ${f.message}`, `  - Fix: ${f.fix}`);
  }
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    toast("Report copied as Markdown");
  } catch {
    toast("Copy failed: clipboard not available");
  }
});
