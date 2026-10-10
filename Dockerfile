FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml ./
COPY sec_agent ./sec_agent
RUN pip install --no-cache-dir ".[web]"

# Both the controller (sec-web, :8000) and the proxy (sec-proxy, :8001) run from
# this one image. docker-compose selects which command + which credentials each
# container gets; that is where the privilege separation lives.
EXPOSE 8000 8001

CMD ["sec-web"]
