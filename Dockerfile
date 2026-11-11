FROM python:3.11-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd -u 10001 app
COPY server server
COPY security security
COPY sentinel sentinel
ENV SENTINEL_BIND=0.0.0.0
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["python", "-m", "server.mcp_server"]
