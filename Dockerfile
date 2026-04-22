FROM python:3.11-slim

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner code
COPY dast_scanner.py .

# Create reports directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ZAP_HOST=zap
ENV ZAP_PORT=8080
ENV SCAN_MODE=docker

ENTRYPOINT ["python", "dast_scanner.py"]
