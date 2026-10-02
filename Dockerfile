# Quanta dashboard image. Runs as a non-root user, serves plain HTTP on :5050 and is meant
# to sit behind a TLS-terminating reverse proxy / ingress (see docs/DEPLOYMENT_ARCHITECTURE.md).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    QUANTA_HOST=0.0.0.0 QUANTA_PORT=5050 QUANTA_DISABLE_TLS=true

WORKDIR /app
COPY dashboard/requirements.txt dashboard/requirements.txt
COPY remediation/connectors/requirements.txt remediation/connectors/requirements.txt
COPY remediation/enrichment/requirements.txt remediation/enrichment/requirements.txt
COPY remediation/config/requirements.txt remediation/config/requirements.txt
RUN pip install --no-cache-dir -r dashboard/requirements.txt -r remediation/connectors/requirements.txt \
    -r remediation/enrichment/requirements.txt -r remediation/config/requirements.txt \
    && pip install --no-cache-dir "psycopg2-binary>=2.9,<3"

COPY . .
RUN useradd --system --create-home --uid 10001 quanta && chown -R quanta:quanta /app
USER quanta

EXPOSE 5050
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5050/api/status', timeout=4).status == 200 else 1)"
CMD ["python", "dashboard/app.py"]
