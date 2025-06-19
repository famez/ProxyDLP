FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create non-root group and user
RUN groupadd -r appgroup && useradd -r -g appgroup -m appuser

# Set working directory
WORKDIR /app

# Copy requirements file first
COPY monitor/requirements.txt .

# Create virtualenv and fix ownership
RUN python -m venv /home/appuser/venv \
    && chown -R appuser:appgroup /home/appuser/venv

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Download grpc_health_probe as root, set permissions for appuser
RUN curl -L https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.11/grpc_health_probe-linux-amd64 \
    -o /usr/local/bin/grpc_health_probe \
    && chmod +x /usr/local/bin/grpc_health_probe \
    && chown appuser:appgroup /usr/local/bin/grpc_health_probe

# Give appuser ownership of /app and pip cache dir
RUN chown -R appuser:appgroup /app \
    && mkdir -p /home/appuser/.cache/pip \
    && chown -R appuser:appgroup /home/appuser/.cache

# Switch to non-root user
USER appuser

# Set PATH to use the virtualenv
ENV PATH="/home/appuser/venv/bin:$PATH"

# Install Python dependencies inside virtualenv
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install grpcio grpcio-tools grpcio-health-checking

# Copy proto files with correct ownership
COPY --chown=appuser:appgroup proto/ proto/

# Generate gRPC code
RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. proto/monitor.proto

# Copy application code with correct ownership
COPY --chown=appuser:appgroup monitor/src/ .

# Switch to root to fix volume mount dir permissions
USER root

# Create the FAISS directory and set proper ownership
RUN mkdir -p /var/faiss && chown -R appuser:appgroup /var/faiss

# Switch back to appuser
USER appuser

RUN pip install readerwriterlock

# Final working directory
WORKDIR /app

# Default command
CMD ["python", "main.py"]
