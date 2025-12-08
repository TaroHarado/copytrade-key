#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for non-interactive mode (CI/CD environment)
FORCE_YES=false
if [[ "$CI" == "true" ]] || [[ "$GITHUB_ACTIONS" == "true" ]] || [[ "$1" == "--force" ]] || [[ "$1" == "-f" ]]; then
    FORCE_YES=true
    print_status "Running in non-interactive mode"
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Starting Privy Signing Service deployment..."

# Set target directory
TARGET_DIR="/opt/polycopy/privy-signing"
print_status "Target directory: $TARGET_DIR"

# В CI/CD режиме мы уже в правильной директории с правильными правами
if [[ "$FORCE_YES" == "true" ]]; then
    print_status "CI/CD mode: working in current directory $(pwd)"
    
    # Проверяем, что мы в правильной директории
    if [[ "$(pwd)" != "$TARGET_DIR" ]]; then
        print_error "Expected to be in $TARGET_DIR, but currently in $(pwd)"
        exit 1
    fi
    
    # Проверяем права доступа к директории
    if [[ ! -w "$TARGET_DIR" ]]; then
        print_error "No write permission to $TARGET_DIR"
        exit 1
    fi
else
    # В локальном режиме проверяем/создаем директорию
    if [[ -d "$TARGET_DIR" ]]; then
        print_warning "Directory $TARGET_DIR already exists."
        read -p "Do you want to continue and overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deployment cancelled."
            exit 0
        fi
    fi
    
    # В локальном режиме создаем директорию (предполагаем что deploy user имеет права)
    if [[ ! -d "$TARGET_DIR" ]]; then
        mkdir -p "$TARGET_DIR"
    fi
    
    # Copy source files
    print_status "Copying privy-signing source files..."
    cp -r ./* "$TARGET_DIR/"
    chmod +x "$TARGET_DIR/deploy.sh"
    chmod +x "$TARGET_DIR/startup_scripts/entrypoint.sh"
    chmod +x "$TARGET_DIR/startup_scripts/wait-for-it.sh"
    
    # Change to target directory
    cd "$TARGET_DIR"
fi

# Create Docker network
print_status "Creating Docker network 'polycopy_network'..."
if docker network inspect polycopy_network >/dev/null 2>&1; then
    print_warning "Network 'polycopy_network' already exists."
else
    docker network create polycopy_network
    print_status "Docker network 'polycopy_network' created."
fi

# Build Docker image locally
print_status "Building Docker image locally..."
docker compose -f docker-compose.yml build

# Stop existing containers
print_status "Stopping existing containers..."
docker compose -f docker-compose.yml down

# Start services
print_status "Starting privy-signing services..."
docker compose -f docker-compose.yml up -d

# Check if services are running
print_status "Checking service status..."
sleep 10

# Проверяем количество запущенных контейнеров (ищем статус "Up" в выводе)
RUNNING_CONTAINERS=$(docker compose -f docker-compose.yml ps | grep -c "Up" || true)

if [ "$RUNNING_CONTAINERS" -ge 2 ]; then
    print_status "✅ Privy Signing services are running successfully! ($RUNNING_CONTAINERS containers running)"
    print_status "You can check the status with: docker compose -f docker-compose.yml ps"
    print_status "View logs with: docker compose -f docker-compose.yml logs"
    
    # Restart nginx container to refresh upstream connections
    print_status "Restarting nginx to refresh privy-signing connections..."
    if docker ps --format "table {{.Names}}" | grep -q "polycopy_nginx"; then
        docker restart polycopy_nginx
        print_status "✅ Nginx container restarted successfully!"
    else
        print_warning "Nginx container 'polycopy_nginx' not found. Skipping nginx restart."
    fi
    
    # Успешно завершаем скрипт
    exit 0
else
    print_error "❌ Some services failed to start. Running containers: $RUNNING_CONTAINERS"
    docker compose -f docker-compose.yml ps
    print_error "Check logs with: docker compose -f docker-compose.yml logs"
    exit 1
fi

# Display useful information
print_status "🎉 Privy Signing Service deployment completed successfully!"
echo

if [[ "$FORCE_YES" != "true" ]]; then
    print_status "Privy Signing Service is now running at: http://localhost:8010"
    print_status "Health check: http://localhost:8010/health"
    print_status "Docker image built locally from source"
    print_status "Database migrations are handled automatically during startup"
    echo
    print_status "Architecture:"
    print_status "  - Privy Signing Service: Isolated microservice for secure signing"
    print_status "  - Docker image: Built locally from source code"
    print_status "  - Docker network: 'polycopy_network' for communication with other services"
    print_status "  - Database: PostgreSQL with automatic migrations"
    print_status "  - Security: IP whitelisting, service token auth, audit logging"
    echo
    print_status "Useful commands:"
    print_status "  View status: cd $TARGET_DIR && docker compose -f docker-compose.yml ps"
    print_status "  View logs: docker compose -f docker-compose.yml logs"
    print_status "  Restart: cd $TARGET_DIR && docker compose -f docker-compose.yml restart"
    print_status "  Stop: cd $TARGET_DIR && docker compose -f docker-compose.yml down"
    print_status "  Database logs: docker compose -f docker-compose.yml logs postgres"
    print_status "  Service logs: docker compose -f docker-compose.yml logs privy-signing"
    print_status "  Rebuild image: docker compose -f docker-compose.yml build"
fi

