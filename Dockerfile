# Stage 1: Build osv-scanner
FROM golang:1.22-alpine as gobuilder

# Set environment for Go modules and binaries
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

# Install git, needed for go install to fetch modules
RUN apk add --no-cache git

# Install osv-scanner
# go install github.com/google/osv-scanner/cmd/osv-scanner@latest
# This command places the binary in $GOPATH/bin/osv-scanner
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Stage 2: Build Python application dependencies and copy osv-scanner
FROM python:3.11-slim-bookworm as pythonbuilder

# Set environment variables for Python
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py
ENV FLASK_ENV production # Production environment for Gunicorn

# Install system dependencies
# git is needed for GitPython during runtime
# build-essential is for any Python packages that might need compilation (e.g., cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy osv-scanner binary from the gobuilder stage to /usr/local/bin
COPY --from=gobuilder /go/bin/osv-scanner /usr/local/bin/osv-scanner
# Make sure it's executable and verify installation
RUN chmod +x /usr/local/bin/osv-scanner && \
    osv-scanner --version

# Set working directory for the app
WORKDIR /app

# Copy application files (only those needed for dependency installation first)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application source code and templates
COPY app.py .
COPY scanner_core.py .
COPY git_handler.py .
COPY .env .env
COPY templates/ templates/

# Final Stage: Lean production image
FROM python:3.11-slim-bookworm

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP app.py
ENV FLASK_ENV production

# Install system dependencies (git is needed for runtime cloning)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy osv-scanner binary from the pythonbuilder stage
COPY --from=pythonbuilder /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
# Ensure it's executable
RUN chmod +x /usr/local/bin/osv-scanner

# Set working directory
WORKDIR /app

# Copy application code and templates from the pythonbuilder stage
COPY --from=pythonbuilder /app/app.py .
COPY --from=pythonbuilder /app/scanner_core.py .
COPY --from=pythonbuilder /app/git_handler.py .
COPY --from=pythonbuilder /app/.env .
COPY --from=pythonbuilder /app/templates/ templates/

# Expose the port Flask/Gunicorn will run on
EXPOSE 5000

# Command to run the application using Gunicorn (a production-ready WSGI server)
# --workers: Number of worker processes (often 2-4 * CPU cores).
# --bind: Listen on all network interfaces on port 5000.
# app:app refers to the Flask app instance named 'app' in 'app.py'.
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", "app:app"]