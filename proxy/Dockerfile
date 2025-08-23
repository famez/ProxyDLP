FROM python:3.11-slim

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_PATH=/home/appuser/venv \
    PATH="/home/appuser/venv/bin:$PATH"

# Create app user and group
RUN groupadd -r appgroup && useradd -r -g appgroup -m appuser

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tmux libmagic1 curl\
    && rm -rf /var/lib/apt/lists/*

# Download grpc_health_probe as root, set permissions for appuser
RUN curl -L https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.11/grpc_health_probe-linux-amd64 \
    -o /usr/local/bin/grpc_health_probe \
    && chmod +x /usr/local/bin/grpc_health_probe \
    && chown appuser:appgroup /usr/local/bin/grpc_health_probe

# Copy requirements.txt with proper ownership
COPY --chown=appuser:appgroup proxy/requirements.txt .

# Create virtualenv and set ownership on /home/appuser and pip cache
RUN python -m venv $VENV_PATH && \
    mkdir -p /home/appuser/.cache/pip && \
    chown -R appuser:appgroup /home/appuser

# Install Python dependencies as appuser
USER appuser
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install grpcio grpcio-tools grpcio-health-checking

# Switch back to root for cert setup and copying other files
USER root

# Copy mitm CA cert files with ownership
COPY --chown=appuser:appgroup proxy/mitmCA.key /tmp/mitmCA.key
COPY --chown=appuser:appgroup proxy/mitmCA.pem /tmp/mitmCA.pem

RUN mkdir -p /home/appuser/.mitmproxy/ && \
    cat /tmp/mitmCA.key /tmp/mitmCA.pem > /home/appuser/.mitmproxy/mitmproxy-ca.pem && \
    chown -R appuser:appgroup /home/appuser/.mitmproxy

# Copy proto and source code with correct ownership
COPY --chown=appuser:appgroup proto/ proto/
COPY --chown=appuser:appgroup proxy/src/ .

# Ensure /app directory and all contents are owned by appuser
RUN chown -R appuser:appgroup /app

RUN mkdir /uploads/
RUN chown -R appuser:appgroup /uploads/

# Switch to appuser and set workdir
USER appuser
WORKDIR /app

# Generate gRPC Python files using the installed venv python
RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. monitor.proto
RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. proxy.proto

CMD ["tmux", "new", "-As", "mitmsession", "mitmproxy", "-s", "main.py"]