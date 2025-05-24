# Use official Python image as a base
FROM python:3.11-slim

# Set environment variables to avoid writing .pyc files and buffering
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy requirements.txt before other files to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

RUN python -m spacy download en_core_web_sm
RUN python -m spacy download es_core_news_sm
RUN python -m spacy download fr_core_news_sm

RUN apt-get update && apt-get install -y tmux

# Copy the rest of your application code

RUN mkdir /etc/proxyGPT/

COPY config/* /etc/proxyGPT/

RUN apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


COPY src/ .


# Set default command (optional, e.g., for running an app.py script)
CMD ["tmux", "new", "-As", "mysession", "mitmproxy", "-s", "proxyGPT.py"]
#CMD ["tmux", "new", "-As", "mysession", "python", "proxyGPT.py"]