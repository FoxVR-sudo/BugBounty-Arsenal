#!/bin/bash
# Stop all Docker Compose services

echo "🛑 Stopping BugBounty Arsenal Docker containers..."
docker-compose down

echo "✅ All containers stopped"
