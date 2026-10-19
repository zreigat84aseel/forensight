# Forensight: phishing email forensics (API and dashboard)
ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

# System libraries: OpenGL/GLib for OpenCV (QR codes), libmagic for file types, zbar for barcodes, YARA for rules
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgl1 libglib2.0-0 libmagic1 libzbar0 yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN mkdir -p /app/output && chmod 777 /app/output

# Never run as root: docker-compose sets the user to the host user's UID
USER 1000:1000
EXPOSE 8000 8501
CMD ["uvicorn", "forensight.api:app", "--host", "127.0.0.1", "--port", "8000"]
