"""CyberNet web app: paste code, get prioritized security findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import scanner
from .analyzers import patterns, secrets
from .ml.features import LABELS, NAMES
from .samples import SAMPLES
from .sarif import to_sarif

VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent


class ScanIn(BaseModel):
    code: str = Field(..., max_length=scanner.MAX_CODE)
    language: Literal["auto", "python", "javascript", "php", "java"] = "auto"
    filename: str | None = Field(None, max_length=200)


app = FastAPI(title="CyberNet", version=VERSION,
              description="AI-augmented static analysis: find vulnerabilities in pasted code and rank them by real risk.")


def run(body: ScanIn) -> dict:
    try:
        return scanner.scan(body.code, body.language, body.filename)
    except ValueError as err:
        raise HTTPException(400, str(err)) from err


@app.post("/api/scan")
def scan(body: ScanIn):
    return run(body)


@app.post("/api/sarif")
def sarif(body: ScanIn):
    data = to_sarif(run(body), VERSION)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(json.dumps(data, indent=2), media_type="application/sarif+json",
                    headers={"Content-Disposition": f'attachment; filename="cybernet-{stamp}.sarif"'})


@app.get("/api/meta")
def meta():
    m = scanner.model()
    python_rules = 18  # sink checks in analyzers/python_ast.py
    secret_rules = len(secrets.PROVIDERS) + 1  # providers + generic credential
    return {
        "version": VERSION,
        "languages": scanner.LANGUAGES,
        "rules": python_rules + secret_rules + sum(len(r) for r in patterns.RULES.values()),
        "model": {
            "type": "Logistic regression", **m.meta,
            "weights": sorted(({"feature": n, "label": LABELS[n], "weight": round(w, 2)} for n, w in zip(NAMES, m.weights)),
                              key=lambda x: -abs(x["weight"])),
        } if m else None,
    }


@app.get("/api/samples")
def samples():
    return SAMPLES


app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(HERE / "static" / "index.html", headers={"Cache-Control": "no-cache"})
