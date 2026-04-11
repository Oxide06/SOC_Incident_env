FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install uv --quiet

# Copy all necessary files
COPY pyproject.toml .
COPY __init__.py .
COPY models.py .
COPY scenarios.py .
COPY tasks.py .
COPY client.py .
COPY server/ ./server/

# Install dependencies + install your own package in editable mode
RUN uv pip install --system "openenv-core[core]>=0.2.2" uvicorn fastapi
RUN uv pip install --system -e .

# Build: 20260411-182035
EXPOSE 8000

# This is the most reliable way for Docker
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]