#!/bin/bash
#
# Run SOC in Docker for development
# First run ./socdev-docker.sh in another terminal to set up VM and SSH tunnel
#

set -e

# Configuration
CONTAINER_NAME=${CONTAINER_NAME:-soc-dev}
IMAGE_NAME=${IMAGE_NAME:-securityonion-soc:dev}
CONFIG_FILE=${CONFIG_FILE:-soc.dev.json}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if manager IP is saved
if [[ ! -f .manager_ip ]]; then
    log_error "No manager IP found. Please run ./socdev-docker.sh first."
    exit 1
fi

MANAGER_IP=$(cat .manager_ip)

# Check if config exists
if [[ ! -f $CONFIG_FILE ]]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_error "Please run ./socdev-docker.sh first to set up the environment."
    exit 1
fi

# Check if Docker image exists
if [[ -z $(docker images -q $IMAGE_NAME 2>/dev/null) ]]; then
    log_warn "Docker image not found. Building..."
    docker build -t $IMAGE_NAME .
fi

# Stop any existing container
if [ -n "$(docker ps -q -f name=$CONTAINER_NAME 2>/dev/null)" ]; then
    log_info "Stopping existing container..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
fi
docker rm $CONTAINER_NAME 2>/dev/null || true

log_info "Starting SOC container..."
log_info "Manager IP: $MANAGER_IP"

# Run the container
docker run -d \
    --name $CONTAINER_NAME \
    -p 9822:9822 \
    -v "$(pwd)/html:/opt/sensoroni/html:ro" \
    -v "$(pwd)/$CONFIG_FILE:/opt/sensoroni/sensoroni.json:ro" \
    -v "$(pwd)/rbac:/opt/sensoroni/rbac:ro" \
    -v "$(pwd)/queue:/opt/sensoroni/queue" \
    -v "$(pwd)/rules:/opt/sensoroni/rules:ro" \
    -v "$(pwd)/strelka:/opt/sensoroni/strelka:ro" \
    -v "$(pwd)/saltstack:/opt/sensoroni/saltstack:ro" \
    -v "$(pwd)/emerging-all.fingerprint:/opt/sensoroni/emerging-all.fingerprint:ro" \
    -v "$(pwd)/sigma.fingerprint:/opt/sensoroni/sigma.fingerprint:ro" \
    -e "ELASTIC_URL=https://$MANAGER_IP:9200" \
    -e "ELASTIC_VERIFYCERT=false" \
    -e "INFLUX_URL=https://$MANAGER_IP:8086" \
    -e "MANAGER_URL=https://$MANAGER_IP" \
    --add-host="elasticsearch:$MANAGER_IP" \
    --add-host="influxdb:$MANAGER_IP" \
    --add-host="manager:$MANAGER_IP" \
    $IMAGE_NAME \
    -c /opt/sensoroni/sensoroni.json

# Wait a moment for container to start
sleep 3

# Check if container is running
if [ -n "$(docker ps -q -f name=$CONTAINER_NAME 2>/dev/null)" ]; then
    log_info "Container started successfully!"
    echo ""
    echo "=========================================="
    echo "Development environment is ready!"
    echo ""
    echo "Access SOC at: https://$MANAGER_IP:9822"
    echo ""
    echo "Logs: docker logs -f $CONTAINER_NAME"
    echo "Shell: docker exec -it $CONTAINER_NAME /bin/bash"
    echo "Stop: docker stop $CONTAINER_NAME"
    echo ""
    echo "Live editing:"
    echo "  - HTML/JS changes: Edit files in ./html/"
    echo "  - Backend changes: Rebuild and restart"
    echo "=========================================="
    echo ""
    echo "Following container logs (Ctrl+C to exit)..."
    echo ""
    docker logs -f $CONTAINER_NAME
else
    log_error "Container exited"
    
    # Check exit code
    EXIT_CODE=$(docker inspect $CONTAINER_NAME --format='{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
    log_error "Exit code: $EXIT_CODE"
    
    echo ""
    echo "Checking logs..."
    LOGS=$(docker logs $CONTAINER_NAME 2>&1)
    if [[ -z "$LOGS" ]]; then
        echo "No logs found. The container may have exited immediately."
        echo ""
        echo "Common causes:"
        echo "  - Missing required files or directories"
        echo "  - Configuration syntax errors"
        echo "  - sensoroni binary issues"
        echo ""
        echo "Try running manually to debug:"
        echo "  docker run --rm -it \\"
        echo "    -v \$(pwd)/soc.dev.json:/opt/sensoroni/sensoroni.json:ro \\"
        echo "    --entrypoint /bin/bash \\"
        echo "    $IMAGE_NAME"
        echo ""
        echo "Then inside container: /opt/sensoroni/sensoroni -c /opt/sensoroni/sensoroni.json"
    else
        echo "$LOGS" | tail -30
    fi
    exit 1
fi