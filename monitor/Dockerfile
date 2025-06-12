# Use official Python image as a base
FROM python:3.11-slim

# Set environment variables to avoid writing .pyc files and buffering
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy requirements.txt before other files to leverage Docker cache
COPY monitor/requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

#RUN python -m spacy download en_core_web_sm
#RUN python -m spacy download es_core_news_sm
#RUN python -m spacy download fr_core_news_sm

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY proto/ proto/

RUN pip install grpcio grpcio-tools grpcio-health-checking

RUN apt-get update && apt-get install -y curl \
  && curl -L https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.11/grpc_health_probe-linux-amd64 -o /usr/local/bin/grpc_health_probe \
  && chmod +x /usr/local/bin/grpc_health_probe

RUN python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. monitor.proto

COPY monitor/src/ .

CMD ["python", "main.py"]