# Agent image: Claude Code + ssh client + kubectl. No secrets, no baked-in credentials.
FROM node:22-bookworm-slim
ARG UID=1000
ARG KUBECTL_VERSION=v1.31.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-client openssh-server netcat-openbsd curl ca-certificates git python3 less procps jq \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && mkdir -p /run/sshd \
    && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && npm install -g @anthropic-ai/claude-code \
    && (id -u ${UID} >/dev/null 2>&1 && userdel -r $(id -un ${UID}) || true) \
    && useradd -m -u ${UID} -s /bin/bash agent
COPY airlock-run /usr/local/bin/airlock-run
RUN chmod 755 /usr/local/bin/airlock-run \
    && echo "Include /airlock/ssh_config" >> /etc/ssh/ssh_config
ENV HOME=/home/agent
USER agent
WORKDIR /workspace
CMD ["sleep", "infinity"]
