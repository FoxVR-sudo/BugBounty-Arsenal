# Multi-stage build: Go tools + Python application
FROM golang:1.21-alpine AS go-builder

# Install Git (required for go install)
RUN apk add --no-cache git

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Final stage: Python application
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei

# Verify tools are executable
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei

# Set working directory
WORKDIR /app

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p recon_output scan_progress screenshots bug_evidence/screenshots reports recon_results raw_responses

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "webapp:app", "--host", "0.0.0.0", "--port", "5000"]
