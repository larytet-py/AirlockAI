# MCP gateway and tool servers (Mode 2). Holds the credentials; the agent container never shares a volume with it.
# Build from the repository root: docker build -f gateway-image/Dockerfile -t airlock-gateway:latest .
FROM python:3.12-slim
ARG UID=1000
ARG KUBECTL_VERSION=v1.31.0
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && (id -u ${UID} >/dev/null 2>&1 && userdel -r $(id -un ${UID}) || true) \
    && useradd -m -u ${UID} -s /bin/bash airlock
COPY pyproject.toml README.md /src/
COPY airlock /src/airlock
COPY operations /src/operations
RUN pip install --no-cache-dir /src && cp -r /src/operations /opt/airlock-operations
ENV AIRLOCK_HOME=/airlock-home AIRLOCK_BUILTIN_OPS=/opt/airlock-operations PYTHONUNBUFFERED=1
USER airlock
EXPOSE 8765
CMD ["python", "-m", "airlock.gwserver"]
