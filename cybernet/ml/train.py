"""Train the prioritization model:  python -m cybernet.ml.train

1. Build the labelled corpus and run the real scanner on every sample to extract features.
2. Evaluate with 5-fold *group* cross-validation: all variants of a template stay in the same
   fold, so the model is always tested on code patterns it never saw during training.
3. Train the final model on everything and save weights + metrics to cybernet/ml/model.json.
"""

from __future__ import annotations

import random
import sys

from ..scanner import raw_findings
from .corpus import TEMPLATES, build
from .features import NAMES, vector
from .model import LogisticRegression, evaluate


def dataset(seed: int = 42):
    X, y, groups, missing = [], [], [], set()
    for language, filename, code, label, idx in build(seed=seed):
        found = raw_findings(code, language, filename)
        if not found:
            missing.add(idx)
            continue
        for f in found:
            X.append(vector(f))
            y.append(label)
            groups.append(idx)
    return X, y, groups, missing


def cross_validate(X, y, groups, k: int = 5, seed: int = 7) -> dict[str, float]:
    ids = sorted(set(groups))
    random.Random(seed).shuffle(ids)
    folds = [set(ids[i::k]) for i in range(k)]
    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for fold in folds:
        tr = [i for i, g in enumerate(groups) if g not in fold]
        te = [i for i, g in enumerate(groups) if g in fold]
        m = LogisticRegression().fit([X[i] for i in tr], [y[i] for i in tr])
        r = evaluate(m, [X[i] for i in te], [y[i] for i in te])
        for key in totals:
            totals[key] += r[key]
    tp, fp, tn, fn = totals["tp"], totals["fp"], totals["tn"], totals["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"accuracy": round((tp + tn) / max(1, tp + fp + tn + fn), 3), "precision": round(precision, 3),
            "recall": round(recall, 3), "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
            **totals}


def main() -> int:
    X, y, groups, missing = dataset()
    if missing:
        print("These templates produced no findings (scanner or template bug):")
        for idx in sorted(missing):
            t = TEMPLATES[idx]
            print(f"  #{idx} [{t.language}] {t.code.splitlines()[-1][:80]}")
        return 1
    print(f"Corpus: {len(X)} findings from {len(set(groups))} templates "
          f"({sum(y)} real, {len(y) - sum(y)} not real), {len(NAMES)} features")
    cv = cross_validate(X, y, groups)
    print(f"5-fold group cross-validation: accuracy {cv['accuracy']:.1%}  precision {cv['precision']:.1%}  "
          f"recall {cv['recall']:.1%}  F1 {cv['f1']:.3f}")
    model = LogisticRegression().fit(X, y)
    model.meta = {"samples": len(X), "templates": len(set(groups)), "positives": sum(y),
                  "cross_validation": cv, "train": evaluate(model, X, y)}
    model.save()
    print("Strongest learned weights:")
    for name, w in sorted(zip(NAMES, model.weights), key=lambda kv: -abs(kv[1]))[:10]:
        print(f"  {name:22} {w:+.2f}")
    print("Saved cybernet/ml/model.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
