#!/usr/bin/env bash
set -euo pipefail

cd /opt/ssh-honeypot
git pull
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y
docker compose -f deploy/docker-compose.yml build --pull
docker compose -f deploy/docker-compose.yml up -d