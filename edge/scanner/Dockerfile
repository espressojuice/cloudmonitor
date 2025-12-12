FROM python:3.11-slim

WORKDIR /app

# Install network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .
COPY app.py .

ENV LOCATION=edge
ENV GATUS_CONFIG_PATH=/config/gatus/config.yaml
ENV MONITORED_FILE=/config/monitored.json

EXPOSE 8081

CMD ["python", "app.py"]
