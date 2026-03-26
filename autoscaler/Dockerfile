FROM docker:cli

# docker:cli is Alpine-based and already ships docker CLI + compose plugin.
# We only need to add Python and the Docker SDK.
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir --break-system-packages docker

WORKDIR /app
COPY autoscaler.py .

CMD ["python3", "-u", "autoscaler.py"]
