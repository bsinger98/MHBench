FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --shell /usr/sbin/nologin auditor
COPY app/ ./
USER auditor
HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=20s \
  CMD test -f /tmp/yard-observer-ready
CMD ["python", "observer.py"]
