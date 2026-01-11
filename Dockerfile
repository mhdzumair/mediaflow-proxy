# Stage 1: Build stage with all compilation dependencies
FROM python:3.14-slim AS builder

# Set work directory
WORKDIR /build

# Install build dependencies required for compiling packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libxml2-dev \
    libxslt-dev \
    zlib1g-dev \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add Rust to PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy only requirements to cache them in docker layer
COPY pyproject.toml uv.lock* /build/

# Install dependencies into a virtual environment
RUN uv sync --frozen --no-install-project --no-dev

# Stage 2: Runtime stage (minimal image)
FROM python:3.14-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE="1"
ENV PYTHONUNBUFFERED="1"
ENV PORT="8888"

# Install only runtime dependencies (no dev packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 mediaflow_proxy

# Set work directory
WORKDIR /mediaflow_proxy

# Copy virtual environment from builder stage
COPY --from=builder /build/.venv /mediaflow_proxy/.venv

# Copy project files
COPY --chown=mediaflow_proxy:mediaflow_proxy . /mediaflow_proxy

# Set ownership
RUN chown -R mediaflow_proxy:mediaflow_proxy /mediaflow_proxy

# Switch to non-root user
USER mediaflow_proxy

# Set up the PATH to include the virtual environment
ENV PATH="/mediaflow_proxy/.venv/bin:$PATH"

# Expose the port the app runs on
EXPOSE 8888

# Run the application with Gunicorn (use python -m to avoid venv path issues)
CMD ["sh", "-c", "exec python -m gunicorn mediaflow_proxy.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8888 --timeout 120 --max-requests 500 --max-requests-jitter 200 --access-logfile - --error-logfile - --log-level info --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
