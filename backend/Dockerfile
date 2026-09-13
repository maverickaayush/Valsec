FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm

RUN sed -i 's|http://deb.debian.org/debian-security|https://security.debian.org/debian-security|; s|http://deb.debian.org/debian|https://ftp.debian.org/debian|' /etc/apt/sources.list.d/debian.sources && \
    apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY alembic.ini .
COPY migrations/ migrations/
RUN useradd --create-home --uid 10001 valsec && chown -R valsec:valsec /app
USER valsec
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
