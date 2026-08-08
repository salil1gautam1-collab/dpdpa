# DPDPA Sentinel — stdlib-only Python, so the image is just the base runtime.
FROM python:3.12-slim

WORKDIR /app
COPY rulebook/ rulebook/
COPY docs/ docs/
COPY samples/ samples/
COPY src/ src/

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

# Client data lives here — mount a volume so it survives container rebuilds
# and stays on YOUR machine (see docs/DATA-PROTECTION-POLICY.md).
VOLUME /app/local

EXPOSE 8377
CMD ["python", "-m", "dpdpa", "serve", "--host", "0.0.0.0", "--port", "8377"]
