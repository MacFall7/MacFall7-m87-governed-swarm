FROM python:3.11-slim

WORKDIR /app

# Copy adapter SDK first (shared dependency)
COPY packages/adapter-sdk /app/packages/adapter-sdk

# Copy adapter requirements and install
COPY services/casey-adapter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e /app/packages/adapter-sdk

# Copy adapter code
COPY services/casey-adapter/app ./app

CMD ["python", "-u", "app/adapter.py"]
