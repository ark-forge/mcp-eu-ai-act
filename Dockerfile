FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY server.py .
COPY manifest.json .
COPY gdpr_module.py .
COPY data/ ./data/

# Run as non-root user
RUN useradd -r -s /bin/false mcp
USER mcp

# Set entrypoint
ENTRYPOINT ["python3", "server.py"]
