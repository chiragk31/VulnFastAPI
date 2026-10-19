# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Metadata
LABEL maintainer="ClairSec Research"
LABEL description="VulnFastAPI — Intentionally vulnerable FastAPI benchmark for ClairSec"

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ ./app/
COPY files/ ./files/
COPY data/ ./data/

# Expose application port
EXPOSE 8000

# Health check so Docker can detect readiness
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
