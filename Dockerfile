FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

RUN useradd --uid 1000 --create-home --home-dir /home/agent --shell /bin/bash agent \
 && mkdir -p /home/agent/workspace /opt/loom-computer \
 && chown -R agent:agent /home/agent

WORKDIR /opt/loom-computer
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY loom_computer ./loom_computer

USER 1000:1000
WORKDIR /home/agent/workspace
ENV PYTHONPATH=/opt/loom-computer

EXPOSE 8787
CMD ["python", "-m", "loom_computer"]
