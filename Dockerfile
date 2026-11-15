# The environment every recorded number was produced in.
#   docker build -t threatrank .
#   docker run --rm -v "$PWD":/work threatrank ./reproduce.sh
FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq fonts-liberation && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout=120 --retries 10 -r /tmp/requirements.txt
WORKDIR /work
