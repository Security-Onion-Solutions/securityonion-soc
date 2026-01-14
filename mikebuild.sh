#!/bin/bash

# Build script for so-soc Docker container
# This script builds the container, transfers it to the host manager, tags it, and restarts so-soc
# Usage: ./mikebuild.sh [--html]
#   --html: Only sync HTML directory contents to manager

set -e  # Exit on error

# Check for --html flag
if [[ "$1" == "--html" ]]; then
    echo "=== Building UI ==="
    (cd ui && npm run build)
    
    echo "=== Syncing HTML directory to manager ==="
    echo "Transferring HTML files to somn24:/opt/so/html/..."
    
    # Use rsync for efficient directory sync, excluding node_modules
    rsync -avz \
          --exclude 'node_modules' \
          --exclude '.git' \
          html/ mreeves@somn24:/opt/so/html/
    
    echo "HTML sync complete!"
    echo "You may need to run 'sudo so-soc-restart' on the manager to see changes."
    exit 0
fi

# Hardcoded version
VERSION="2.4.210"

echo "=== Starting so-soc Docker build process ==="
echo "Building version: $VERSION"

# Step 1: Build the Docker container with version argument
echo "Building Docker container..."
docker build --build-arg VERSION=$VERSION -t so-soc:latest .

# Step 2: Save the Docker image to a tar file
echo "Saving Docker image to tar file..."
docker save so-soc:latest -o so-soc.tar

# Step 3: SCP the tar file to the host manager using onion user
# Using onion user since it has SSH keys and passwordless sudo configured
echo "Transferring image to host manager..."
scp so-soc.tar mreeves@somn24:/tmp/so-soc.tar

# Step 4: Load and tag the image on the manager
echo "Loading and tagging image on manager..."
ssh mreeves@somn24 "sudo docker load -i /tmp/so-soc.tar && \
                    sudo docker tag so-soc:latest somn24:5000/security-onion-solutions/so-soc:2.4.210 && \
                    rm /tmp/so-soc.tar"

# Step 5: Restart so-soc service
echo "Restarting so-soc service..."
ssh mreeves@somn24 "sudo so-soc-restart --force"

# Cleanup local tar file
echo "Cleaning up local tar file..."
rm -f so-soc.tar

echo "=== Build and deployment complete! ==="
