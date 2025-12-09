#!/bin/sh

# Debugging step to list contents of /app
ls -l /app

# Verify wait-for-it.sh exists and is executable
if [ -f /app/startup_scripts/wait-for-it.sh ]; then
    echo "wait-for-it.sh found"
else
    echo "wait-for-it.sh not found"
    exit 1
fi

# Wait for PostgreSQL to be ready
/app/startup_scripts/wait-for-it.sh postgres:5432 --strict --timeout=60 -- echo "Database is up"

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

# Check DEBUG environment variable
if [ "$DEBUG" = "true" ]; then
    echo "DEBUG mode enabled - starting with reload"
    uvicorn main:app --host 0.0.0.0 --port 8010 --reload --proxy-headers
else
    echo "Production mode - starting Privy Signing Service"
    uvicorn main:app --host 0.0.0.0 --port 8010 --workers 2 --proxy-headers
fi



