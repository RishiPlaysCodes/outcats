# outcats web dashboard - minimal, dependency-free image.
FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Cloud platforms inject $PORT; bind to all interfaces inside the container.
ENV HOST=0.0.0.0 \
    PORT=8787
EXPOSE 8787

# OUTCATS_TOKEN should be provided as an env var/secret by the platform so the
# public instance requires a token. The CMD reads HOST/PORT/OUTCATS_TOKEN.
CMD ["outcats", "gui"]
