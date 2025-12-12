FROM python:3.11-slim

WORKDIR /app

# Install network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .

# Default environment
ENV LOCATION=edge
ENV SCAN_INTERVAL_HOURS=1

ENTRYPOINT ["python", "scanner.py"]
CMD ["--output", "/config/gatus/config.yaml"]
