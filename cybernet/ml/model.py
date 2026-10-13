"""Logistic regression, implemented from scratch (no numpy/scikit-learn needed).

    p(real & exploitable) = sigmoid(w · x + b)

Trained with batch gradient descent and L2 regularization. Being linear, every prediction
can be explained exactly: each feature contributes wᵢ·xᵢ to the score.
"""

from __future__ import annotations

import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .features import LABELS, NAMES

MODEL_PATH = Path(__file__).with_name("model.json")


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1 / (1 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1 + ez)


class LogisticRegression:
    def __init__(self, weights: list[float] | None = None, bias: float = 0.0, meta: dict[str, Any] | None = None):
        self.weights = weights or [0.0] * len(NAMES)
        self.bias = bias
        self.meta = meta or {}

    def fit(self, X: list[list[float]], y: list[int], epochs: int = 3000, lr: float = 0.5, l2: float = 0.01,
            seed: int = 0) -> "LogisticRegression":
        rnd = random.Random(seed)
        n, d = len(X), len(X[0])
        self.weights = [rnd.uniform(-0.01, 0.01) for _ in range(d)]
        self.bias = 0.0
        pos = sum(y)
        # Weight classes so an imbalanced corpus doesn't bias the model toward the majority label.
        w_pos, w_neg = n / (2 * pos), n / (2 * (n - pos))
        for _ in range(epochs):
            grad_w = [0.0] * d
            grad_b = 0.0
            for xi, yi in zip(X, y):
                err = (sigmoid(self._z(xi)) - yi) * (w_pos if yi else w_neg)
                for j in range(d):
                    grad_w[j] += err * xi[j]
                grad_b += err
            for j in range(d):
                self.weights[j] -= lr * (grad_w[j] / n + l2 * self.weights[j])
            self.bias -= lr * grad_b / n
        return self

    def _z(self, x: list[float]) -> float:
        return sum(w * v for w, v in zip(self.weights, x)) + self.bias

    def predict_proba(self, x: list[float]) -> float:
        return sigmoid(self._z(x))

    def explain(self, x: list[float], top: int = 4) -> list[dict[str, Any]]:
        """The features that moved this prediction the most, in plain words."""
        # Category terms are per-class baselines, not reasons a user can act on: leave them out.
        contributions = [(NAMES[j], self.weights[j] * x[j]) for j in range(len(x)) if x[j] and not NAMES[j].startswith("cat_")]
        contributions.sort(key=lambda kv: abs(kv[1]), reverse=True)
        return [{"feature": name, "label": LABELS[name], "effect": round(c, 2), "direction": "up" if c > 0 else "down"}
                for name, c in contributions[:top] if abs(c) >= 0.05]

    # ---------- persistence ----------
    def save(self, path: Path = MODEL_PATH) -> None:
        path.write_text(json.dumps({
            "type": "logistic_regression", "features": NAMES,
            "weights": [round(w, 6) for w in self.weights], "bias": round(self.bias, 6),
            "meta": {**self.meta, "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        }, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "LogisticRegression":
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["features"] != NAMES:
            raise ValueError("model.json was trained on different features: run `python -m cybernet.ml.train`")
        return cls(data["weights"], data["bias"], data.get("meta", {}))


def evaluate(model: LogisticRegression, X: list[list[float]], y: list[int], threshold: float = 0.5) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for xi, yi in zip(X, y):
        pred = model.predict_proba(xi) >= threshold
        if pred and yi:
            tp += 1
        elif pred and not yi:
            fp += 1
        elif not pred and yi:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "accuracy": round((tp + tn) / len(y), 3) if y else 0.0,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }
