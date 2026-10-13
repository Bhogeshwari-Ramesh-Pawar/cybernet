FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Runtime only needs FastAPI + Uvicorn (httpx and pytest are for tests).
RUN pip install --no-cache-dir fastapi==0.115.6 "uvicorn[standard]==0.34.0"

COPY cybernet ./cybernet

RUN useradd --create-home --uid 10001 cybernet
USER cybernet

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/meta')"
CMD ["uvicorn", "cybernet.main:app", "--host", "0.0.0.0", "--port", "8001"]
