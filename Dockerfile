# Use a slim Python image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the dashboard port
EXPOSE 8000

# Run AgentX
# Note: --host 0.0.0.0 is used to listen on all interfaces within the container
CMD ["python3", "-m", "uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8000"]
