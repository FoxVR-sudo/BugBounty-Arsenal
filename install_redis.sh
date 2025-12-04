#!/bin/bash
# Quick Redis installation script for BugBounty Arsenal

echo "=========================================="
echo "Redis Installation Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please don't run this script as root (without sudo)"
    echo "Run as: ./install_redis.sh"
    exit 1
fi

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    echo "Detected OS: $OS"
else
    echo "Cannot detect OS"
    exit 1
fi

# Install Redis based on OS
echo ""
echo "Installing Redis..."

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Mint"* ]]; then
    echo "Using apt package manager..."
    sudo apt-get update
    sudo apt-get install -y redis-server
    
    # Enable Redis service
    sudo systemctl enable redis-server
    sudo systemctl start redis-server
    
elif [[ "$OS" == *"Fedora"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"CentOS"* ]]; then
    echo "Using yum/dnf package manager..."
    sudo yum install -y redis || sudo dnf install -y redis
    
    # Enable Redis service
    sudo systemctl enable redis
    sudo systemctl start redis
    
elif [[ "$OS" == *"Arch"* ]]; then
    echo "Using pacman package manager..."
    sudo pacman -S --noconfirm redis
    
    # Enable Redis service
    sudo systemctl enable redis
    sudo systemctl start redis
    
else
    echo "Unsupported OS: $OS"
    echo "Please install Redis manually:"
    echo "  https://redis.io/docs/getting-started/installation/"
    exit 1
fi

# Check if Redis is running
echo ""
echo "Checking Redis status..."
sleep 2

if redis-cli ping > /dev/null 2>&1; then
    echo "✓ Redis is running!"
    echo ""
    redis-cli --version
    echo ""
    echo "Redis server is ready for Celery."
else
    echo "✗ Redis installation may have failed."
    echo "Try manually:"
    echo "  sudo systemctl start redis-server"
    echo "  redis-cli ping"
    exit 1
fi

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo ""
echo "1. Start Celery worker:"
echo "   source .venv/bin/activate"
echo "   celery -A config worker --loglevel=info"
echo ""
echo "2. Start Django server (in another terminal):"
echo "   python manage.py runserver"
echo ""
echo "3. Create a test scan via API"
echo ""
echo "=========================================="
