FROM python:3.13.5-slim

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/mediaflow_proxy/.local/bin:$PATH"

# Diretório de trabalho
WORKDIR /mediaflow_proxy

# Usuário não-root
RUN useradd -m mediaflow_proxy
USER mediaflow_proxy

# Instalar dependências
COPY pyproject.toml poetry.lock* /mediaflow_proxy/
RUN pip install --user poetry \
    && poetry config virtualenvs.in-project true \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copiar o restante do projeto
COPY . /mediaflow_proxy

# Expõe a porta dinâmica do Railway
EXPOSE $PORT

# Comando mínimo para o Railway Free
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$PORT"]
