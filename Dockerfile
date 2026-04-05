FROM python:3.11-slim

WORKDIR /app

RUN pip install uv --quiet

COPY pyproject.toml .
COPY __init__.py .
COPY models.py .
COPY scenarios.py .
COPY tasks.py .
COPY client.py .
COPY server/ ./server/

RUN uv pip install --system \
    "openenv-core[core]>=0.2.2" \
    "uvicorn>=0.24.0" \
    "fastapi>=0.104.0"

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
