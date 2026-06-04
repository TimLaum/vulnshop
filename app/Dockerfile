FROM python:3.9-slim

# Remédiation : patcher les paquets système (CVE OS niveau CRITICAL/HIGH, ex. OpenSSL)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# DS-0002 : exécuter avec un utilisateur non-root
RUN adduser --disabled-password --gecos '' appuser
USER appuser

EXPOSE 5000

# DS-0026 : healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/debug')" || exit 1

CMD ["python", "app.py"]
