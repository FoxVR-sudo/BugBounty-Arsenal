#!/bin/bash
# Quick start script for Docker Compose

echo "🐳 Starting BugBounty Arsenal with Docker Compose..."

# Stop any running local servers
echo "📛 Stopping local servers..."
pkill -f "runserver" 2>/dev/null
pkill -f "celery.*worker" 2>/dev/null
pkill -f "node.*react-scripts" 2>/dev/null

# Start Docker Compose (v2 syntax)
echo "🚀 Starting Docker containers..."
sudo docker compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check status
echo ""
echo "✅ Services status:"
sudo docker compose ps

echo ""
echo "📊 Service URLs:"
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://127.0.0.1:8001"
echo "  API Docs:  http://127.0.0.1:8001/api/docs/"
echo ""
echo "📝 Useful commands:"
echo "  View logs:       sudo docker compose logs -f"
echo "  Stop services:   sudo docker compose down (or ./docker-stop.sh)"
echo "  Restart:         sudo docker compose restart"
echo "  Shell (backend): sudo docker compose exec backend bash"
echo ""
