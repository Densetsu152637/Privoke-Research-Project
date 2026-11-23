#!/usr/bin/env bash
# Run once as root on a Debian 12 Compute Engine VM.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
apt-get update
apt-get install -y ca-certificates curl gnupg openssl python3 python3-venv
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
printf '%s\n' "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor --yes -o /etc/apt/keyrings/google-cloud.gpg
printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt cloud-sdk main' > /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin google-cloud-cli
systemctl enable --now docker
install -d -m 0700 /opt/privoke /opt/privoke/releases
# Staging directories of the V3 routine-training stack (stage V3-R7); the operator fills them, see deploy/gce/.env.example.
install -d -m 0700 /opt/privoke/model-releases /opt/privoke/v3-originals /opt/privoke/v3-retention-bank
# The smoke test (deploy/gce/tests/smoke.py) runs from here on every deployment. Versions match the service images.
python3 -m venv /opt/privoke/smoke-venv
/opt/privoke/smoke-venv/bin/pip install --no-cache-dir grpcio==1.82.1 grpcio-tools==1.82.1 protobuf==7.35.1
docker compose version
