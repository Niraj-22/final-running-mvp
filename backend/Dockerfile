# -------------------------
# BASE IMAGE
# -------------------------
FROM python:3.11-slim

# -------------------------
# ENVIRONMENT
# -------------------------
WORKDIR /app

# Prevents Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Forces Python output to be flushed directly
ENV PYTHONUNBUFFERED=1

# -------------------------
# SYSTEM DEPENDENCIES
# -------------------------
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# -------------------------
# COPY REQUIREMENTS
# -------------------------
COPY requirements.txt .

# -------------------------
# INSTALL DEPENDENCIES
# -------------------------
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------
# COPY APPLICATION
# -------------------------
COPY . .

# -------------------------
# EXPOSE PORT
# -------------------------
EXPOSE 8000

# -------------------------
# START FASTAPI
# -------------------------
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
