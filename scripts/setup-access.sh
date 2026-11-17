#!/usr/bin/env bash
# Install your SSH public key and a NOPASSWD sudoers drop-in on EC2 nodes.
# Usage: ./scripts/setup-access.sh host1 host2 ...
# Prompts once for username and password (used for both ssh login and sudo).
# Requires: sshpass, an ssh public key in ~/.ssh/*.pub
set -u

command -v sshpass >/dev/null || { echo "sshpass not installed (apt install sshpass)" >&2; exit 1; }
[ $# -gt 0 ] || { echo "usage: $0 host [host...]" >&2; exit 1; }

read -rp "Username [${USER}]: " U
U=${U:-$USER}
read -rsp "Password for ${U}: " SSHPASS; echo
export SSHPASS

PUBKEYS=$(cat ~/.ssh/*.pub 2>/dev/null)
[ -n "$PUBKEYS" ] || { echo "no public keys in ~/.ssh" >&2; exit 1; }

# sudoers.d ignores filenames containing '.' or '~', so arkady.m -> zz_arkady_m
# (filename only; the username inside the file keeps its dot)
FNAME="zz_$(printf '%s' "$U" | tr -c 'A-Za-z0-9_-' '_')"
LINE="${U} ALL=(ALL) NOPASSWD:ALL"

# Remote step 1 (as user): append keys to authorized_keys, skipping duplicates.
KEYS_CMD="umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; \
while IFS= read -r k; do [ -n \"\$k\" ] && { grep -qxF \"\$k\" ~/.ssh/authorized_keys || echo \"\$k\" >> ~/.ssh/authorized_keys; }; done <<'KEYS'
${PUBKEYS}
KEYS"

# Remote step 2 (as root via sudo -S): validate with visudo, then install.
SUDO_CMD="t=\$(mktemp) && echo '${LINE}' > \$t && visudo -cf \$t >/dev/null && install -m 0440 -o root -g root \$t /etc/sudoers.d/${FNAME}; rc=\$?; rm -f \$t; exit \$rc"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password,keyboard-interactive,publickey)

for host in "$@"; do
  echo "== ${host}"
  sshpass -e ssh "${SSH_OPTS[@]}" "${U}@${host}" "$KEYS_CMD" || { echo "FAIL ssh/keys: ${host}"; continue; }
  # stdin is the sudo password; sudo -S reads it, -p '' suppresses the prompt
  printf '%s\n' "$SSHPASS" | sshpass -e ssh "${SSH_OPTS[@]}" "${U}@${host}" \
      "sudo -S -p '' bash -c '${SUDO_CMD}'" || { echo "FAIL sudoers (wrong sudo password or not a sudoer): ${host}"; continue; }
  ssh -o BatchMode=yes "${U}@${host}" 'sudo -n true' \
    && echo "OK: key login + passwordless sudo on ${host}" \
    || echo "WARN: installed but verification failed on ${host}"
done
unset SSHPASS
