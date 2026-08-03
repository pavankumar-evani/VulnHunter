# VulnShop demo Dockerfile — intentionally contains bad practices for VulnHunter to catch:
#   - runs as root (no USER directive)              -> CWE-250
#   - secret baked into image via ENV                -> CWE-798
#   - uses an old, unpinned base image tag            -> supply chain risk
#   - installs deps without hash verification

FROM python:3.9

WORKDIR /app

# FIXED (VULN-8, CWE-798): no secret baked into the image. Pass STRIPE_API_KEY at
# `docker run -e STRIPE_API_KEY=...` time instead, or via a secrets manager.
# FIXED (VULN-5, CWE-489): debug now off by default; app.py reads this at runtime.
ENV FLASK_DEBUG=0

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# FIXED (VULN-7, CWE-250): drop root privileges before running the app.
RUN useradd --create-home appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
