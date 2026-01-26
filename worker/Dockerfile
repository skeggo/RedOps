FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates curl unzip tar git jq procps perl \
  python3 python3-venv python3-pip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# venv to avoid PEP 668 restrictions
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY worker/install-tools.sh /usr/local/bin/install-tools
COPY worker/tools.yaml /app/tools.yaml
RUN chmod +x /usr/local/bin/install-tools && /usr/local/bin/install-tools /app/tools.yaml

# Verify tools exist in PATH and are runnable
RUN httpx -h >/dev/null && katana -h >/dev/null && nuclei -h >/dev/null && ffuf -h >/dev/null

COPY worker/ /app/
COPY common/ /app/common/
CMD ["python3", "worker.py"]