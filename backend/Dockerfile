FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY bulk_ioc_scanner/ ./bulk_ioc_scanner/

EXPOSE 8000

CMD ["uvicorn", "bulk_ioc_scanner.main:app", "--host", "0.0.0.0", "--port", "8000"]
