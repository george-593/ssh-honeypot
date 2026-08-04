cd /opt/ssh-honeypot
git pull
apt-get update && apt-get upgrade -y
docker compose -f deploy/docker-compose.yml build --pull
docker compose -f deploy/docker-compose.yml up -d