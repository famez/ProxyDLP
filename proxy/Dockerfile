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

# Copy the rest of your application code

RUN openssl genrsa -out /tmp/mitmCA.key 4096
RUN openssl req -x509 -new -nodes -key /tmp/mitmCA.key -sha256 -days 1825 -out /tmp/mitmCA.pem -subj "/CN=MyMITMProxyCA"
RUN mkdir ~/.mitmproxy/
RUN cat /tmp/mitmCA.key /tmp/mitmCA.pem > ~/.mitmproxy/mitmproxy-ca.pem

COPY proto/ proto/


RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. monitor.proto

COPY proxy/src/ .

CMD ["tmux", "new", "-As", "mitmsession", "mitmproxy", "-s", "main.py"]
#CMD ["python", "main.py"]