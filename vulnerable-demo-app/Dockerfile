# VulnShop demo Dockerfile — intentionally contains bad practices for VulnHunter to catch:
#   - runs as root (no USER directive)              -> CWE-250
#   - secret baked into image via ENV                -> CWE-798
#   - uses an old, unpinned base image tag            -> supply chain risk
#   - installs deps without hash verification

FROM python:3.9

WORKDIR /app

# VULN: secret baked directly into the image layer
ENV STRIPE_API_KEY="sk_live_DEMO_FAKE_NOT_A_REAL_KEY_1234567890"
ENV FLASK_DEBUG=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# VULN: no USER instruction -> container runs as root by default
EXPOSE 5000

CMD ["python", "app.py"]
