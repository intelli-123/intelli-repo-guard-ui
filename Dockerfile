# Stage 1: Build osv-scanner
FROM golang:1.22-alpine as gobuilder

# Install git, needed for go install to fetch modules
RUN apk add --no-cache git

# Install osv-scanner v2
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest


# Stage 2: Final Production Image
FROM python:3.11-slim-bookworm

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Install system dependencies (git is strictly needed for git_handler.py)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy osv-scanner binary from the gobuilder stage to /usr/local/bin
COPY --from=gobuilder /go/bin/osv-scanner /usr/local/bin/osv-scanner
RUN chmod +x /usr/local/bin/osv-scanner

# Set working directory for the app
WORKDIR /app

# Copy requirements and install Python dependencies
# Note: Added gunicorn here just in case it's missing from your requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application files (Notice we DO NOT copy .env)
COPY app.py .
COPY scanner_core.py .
COPY git_handler.py .
COPY templates/ templates/

# Expose the port Flask/Gunicorn will run on
EXPOSE 5000

# Command to run the application using Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "app:app"]