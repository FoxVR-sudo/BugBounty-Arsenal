#!/bin/bash
# BugBounty Arsenal Production Deployment Script
# Server: 164.138.221.48 | Domain: bugbaunty-arsenal.com

set -e

echo "=== Installing Docker and Dependencies ==="
apt-get update
apt-get install -y ca-certificates curl gnupg git nginx certbot python3-certbot-nginx

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
systemctl enable docker
systemctl start docker

echo "=== Docker installed successfully ==="
docker --version
docker compose version

echo "=== Creating application directory ==="
mkdir -p /opt/bugbounty-arsenal
cd /opt/bugbounty-arsenal

echo "=== Setup complete! ==="
echo "Next: Clone repository and configure nginx"
