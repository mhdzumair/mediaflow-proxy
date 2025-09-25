FROM python:3.13.5-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/mediaflow_proxy/.local/bin:$PATH"

# Set work directory
WORKDIR /mediaflow_proxy

# Create a non-root user
RUN useradd -m mediaflow_proxy
RUN chown -R mediaflow_proxy:mediaflow_proxy /mediaflow_proxy

# Switch to non-root user
USER mediaflow_proxy

# Install Poetry
RUN pip install --user --no-cache-dir poetry

# Copy project metadata to leverage caching
COPY --chown=mediaflow_proxy:mediaflow_proxy pyproject.toml poetry.lock* /mediaflow_proxy/

# Install dependencies
RUN poetry config virtualenvs.in-project true \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy project files
COPY --chown=mediaflow_proxy:mediaflow_proxy . /mediaflow_proxy

# Expose port (optional, for documentation)
EXPOSE $PORT

# Start the application using Gunicorn with Uvicorn workers
CMD ["sh", "-c", "exec poetry run gunicorn mediaflow_proxy.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120 --max-requests 500 --max-requests-jitter 200 --access-logfile - --error-logfile - --log-level info --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
