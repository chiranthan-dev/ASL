# ASL — Adaptive Security Layer
# Builds a self-contained demo image. The planner is the deterministic mock by
# default (no model server needed in the cloud); set ASL_MOCK_LLM=false plus an
# OpenAI-compatible endpoint to drive a live model.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Cloud hosts inject the port to bind on.
ENV PORT=8000
EXPOSE 8000

# Bind to all interfaces so the platform can route to it.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
