# Use official Python image as a base
FROM python:3.11-slim

# Set environment variables to avoid writing .pyc files and buffering
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy requirements.txt before other files to leverage Docker cache
COPY proxy/requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt


RUN apt-get update && apt-get install -y tmux


COPY proxy/mitmCA.key /tmp/mitmCA.key
COPY proxy/mitmCA.pem /tmp/mitmCA.pem

RUN mkdir ~/.mitmproxy/
RUN cat /tmp/mitmCA.key /tmp/mitmCA.pem > ~/.mitmproxy/mitmproxy-ca.pem

COPY proto/ proto/


RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. monitor.proto

COPY proxy/src/ .

CMD ["tmux", "new", "-As", "mitmsession", "mitmproxy", "-s", "main.py"]
#CMD ["python", "main.py"]