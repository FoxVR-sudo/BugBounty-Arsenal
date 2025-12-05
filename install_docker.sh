#!/bin/bash
# Docker Installation Script for Linux Mint / Ubuntu

set -e

echo "=========================================="
echo "Installing Docker and Docker Compose"
echo "=========================================="

# Update package index
echo "Updating package index..."
sudo apt-get update

# Install prerequisites
echo "Installing prerequisites..."
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
echo "Adding Docker GPG key..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up Docker repository (using Ubuntu focal for Linux Mint compatibility)
echo "Setting up Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$UBUNTU_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package index again
echo "Updating package index with Docker repository..."
sudo apt-get update

# Install Docker Engine
echo "Installing Docker Engine..."
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add current user to docker group
echo "Adding current user to docker group..."
sudo usermod -aG docker $USER

# Start and enable Docker service
echo "Starting Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Verify installation
echo ""
echo "=========================================="
echo "Verifying Docker installation..."
echo "=========================================="
docker --version
docker compose version

echo ""
echo "=========================================="
echo "Docker Installation Complete!"
echo "=========================================="
echo ""
echo "IMPORTANT: You need to log out and log back in for group changes to take effect."
echo "Or run: newgrp docker"
echo ""
echo "After that, you can run:"
echo "  docker run hello-world"
echo "  docker-compose up"
echo ""
echo "To start BugBounty Arsenal:"
echo "  docker-compose up -d --build"
echo ""
