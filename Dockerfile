FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for building and database
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app

# Expose app port
EXPOSE 8000

# Default command (overridden by docker-compose)
CMD ["gunicorn", "deploy_platform.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]