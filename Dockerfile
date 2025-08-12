# syntax=docker/dockerfile:1.7

############################
# Builder: install deps into a venv
############################
FROM python:3.12-slim-bookworm AS builder

ENV VENV_PATH=/opt/venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System dependencies needed for psycopg2 (and compiling wheels when needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Create virtualenv and install Python deps
RUN python -m venv $VENV_PATH
ENV PATH="$VENV_PATH/bin:$PATH"

WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

############################
# Final runtime image
############################
FROM python:3.12-slim-bookworm AS final

# Use the prebuilt venv from the builder layer
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QR_CODE_DIR=/myapp/qr_codes

# Create a non-root user
RUN useradd -m -u 10001 appuser

WORKDIR /myapp

# Copy only the virtualenv first (stays cached when code changes)
COPY --from=builder /opt/venv /opt/venv

# Copy the application code
COPY --chown=appuser:appuser . .

USER appuser

# Expose the API port
EXPOSE 8000

# Start the app (adjust module if your entrypoint differs)
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000", "--workers", "2"]
