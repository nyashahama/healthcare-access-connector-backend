#!/bin/bash

# Healthcare Access Connector - Development Setup Script
# This script sets up your local development environment

set -e  # Exit on error

echo "=================================="
echo "Healthcare Access Connector"
echo "Development Environment Setup"
echo "=================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    echo "   Visit: https://golang.org/doc/install"
    exit 1
fi

echo "✓ Docker is installed"
echo "✓ Docker Compose is installed"
echo "✓ Go is installed"
echo ""

# Create symlink to development environment
if [ ! -f .env ] && [ ! -L .env ]; then
    echo "📝 Creating .env symlink to .env.development..."
    ln -s .env.development .env
    echo "✓ .env symlink created"
    echo ""
    echo "⚠️  IMPORTANT: Generate a secure JWT_SECRET:"
    echo "   Run: make generate-jwt"
    echo "   Then update JWT_SECRET in .env.development"
elif [ -L .env ]; then
    target=$(readlink .env)
    echo "ℹ️  .env is already a symlink pointing to: $target"
else
    echo "⚠️  .env file already exists (not a symlink), skipping..."
fi
echo ""

# Install Go dependencies
echo "📦 Installing Go dependencies..."
go mod download
go mod tidy
echo "✓ Dependencies installed"
echo ""

# Stop any existing containers
echo "🧹 Cleaning up any existing containers..."
docker-compose down 2>/dev/null || true
echo ""

# Start Docker services
echo "🐳 Starting Docker services..."
docker-compose up -d postgres redis nats mailpit
echo "✓ Docker services starting..."
echo ""

# Wait for services to be ready
echo "⏳ Waiting for services to be healthy..."
sleep 5

# Check PostgreSQL
echo "Checking PostgreSQL..."
max_attempts=30
attempt=0
until docker exec hac_postgres pg_isready -U postgres &> /dev/null; do
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ PostgreSQL failed to start"
        exit 1
    fi
    echo "  Waiting for PostgreSQL... ($attempt/$max_attempts)"
    sleep 2
done
echo "✓ PostgreSQL is ready"

# Check Redis
echo "Checking Redis..."
attempt=0
until docker exec hac_redis redis-cli ping &> /dev/null; do
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo "❌ Redis failed to start"
        exit 1
    fi
    echo "  Waiting for Redis... ($attempt/$max_attempts)"
    sleep 2
done
echo "✓ Redis is ready"

echo ""
echo "=================================="
echo "✓ Setup Complete!"
echo "=================================="
echo ""
echo "Your local services are running:"
echo ""
echo "  🗄️  PostgreSQL:       localhost:5432 (postgres/admin)"
echo "  🔴 Redis:            localhost:6379"
echo "  📧 Mailpit UI:       http://localhost:8025"
echo "  📨 NATS:             localhost:4222"
echo ""
echo "Next steps:"
echo ""
echo "  1. Generate JWT secret:  make generate-jwt"
echo "  2. Update .env with the generated JWT_SECRET"
echo "  3. Run migrations:       make migrate-up"
echo "  4. Start the app:        make dev"
echo ""
echo "Or simply run:"
echo "  make dev"
echo ""
echo "The app will automatically:"
echo "  ✓ Start Docker services"
echo "  ✓ Connect to local PostgreSQL"
echo "  ✓ Connect to local Redis"
echo "  ✓ Send emails to Mailpit (view at http://localhost:8025)"
echo ""
echo "To stop services:"
echo "  make docker-down"
echo ""
echo "For more commands:"
echo "  make help"
echo ""
