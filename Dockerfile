# Cyber Mistake Detector - Production Docker Image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    FLASK_ENV=production

WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application source code
COPY . .

# Expose web service port
EXPOSE 5000

# Health check to ensure service is alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Production WSGI server command
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120"]
