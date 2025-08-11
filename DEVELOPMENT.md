# Security Onion Console Development Guide

This guide explains how to set up a local development environment for Security Onion Console (SOC) using Docker, allowing you to make live changes to the frontend while running the backend in a container.

## Overview

We provide three different approaches for local SOC development:

1. **socdev-hybrid.sh** (Recommended) - Simple Docker-based development with live frontend editing
2. **socdev-docker.sh** - Full Docker setup with remote Security Onion integration
3. **docker-compose.dev.yml** - Docker Compose based development environment

## Quick Start (socdev-hybrid.sh)

The hybrid approach is the simplest way to get started:

```bash
# First time setup - build the Docker image
./socdev-hybrid.sh build

# Start the development environment
./socdev-hybrid.sh start --manager-ip <YOUR_SO_MANAGER_IP>

# View logs
./socdev-hybrid.sh logs

# Stop when done
./socdev-hybrid.sh stop
```

### Features

- ✅ Backend runs in Docker (consistent environment)
- ✅ Frontend files mounted for live editing
- ✅ No need to rebuild for JS/HTML/CSS changes
- ✅ Simple command-line interface
- ✅ Automatic configuration generation

### Live Editing

With the hybrid setup, you can edit these files and see changes immediately (after browser refresh):

- `html/js/**/*.js` - All JavaScript files
- `html/css/**/*.css` - All stylesheets  
- `html/pages/**/*.html` - All HTML templates
- `html/images/**/*` - All images

Backend changes (Go code) require rebuilding:

```bash
./socdev-hybrid.sh build --rebuild
./socdev-hybrid.sh restart
```

## Advanced Setup (socdev-docker.sh)

For deeper integration with a remote Security Onion instance:

```bash
./socdev-docker.sh --manager-ip <YOUR_SO_MANAGER_IP>
```

This script:
- Mounts remote SO directories via SSHFS
- Sets up SSH tunnels for service access
- Stops the remote SOC container
- Runs your local development container

## Docker Compose Setup

For more control over the development environment:

```bash
# Set environment variables
export MANAGER_IP=<YOUR_SO_MANAGER_IP>
export TMP_DIR=/tmp/socdev

# Start services
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop services
docker-compose -f docker-compose.dev.yml down
```

## Development Workflow

### 1. Frontend Development

Edit files in the `html/` directory:

```
html/
├── js/
│   ├── routes/       # Vue.js route components
│   ├── components/   # Reusable components
│   ├── app.js       # Main application
│   └── i18n.js      # Internationalization
├── css/             # Stylesheets
├── pages/           # HTML templates
└── images/          # Static images
```

Changes are reflected immediately after browser refresh.

### 2. Backend Development

1. Make changes to Go code
2. Rebuild the image: `./socdev-hybrid.sh build --rebuild`
3. Restart the container: `./socdev-hybrid.sh restart`

### 3. Configuration Changes

Edit `soc.dev.json` and restart the container to apply changes.

## Connecting to Services

The development container needs access to:

- **Elasticsearch** (port 9200)
- **InfluxDB** (port 8086)  
- **Kratos** (port 4434)
- **Hydra** (port 4445)

These are typically running on your Security Onion manager.

## Troubleshooting

### Container won't start

Check logs: `./socdev-hybrid.sh logs`

Common issues:
- Port 9822 already in use
- Cannot connect to Elasticsearch
- Missing configuration file

### Changes not reflecting

- Frontend: Hard refresh browser (Ctrl+Shift+R)
- Backend: Ensure you rebuilt and restarted container
- Check browser console for JavaScript errors

### Permission issues

The container runs as user `socore` (UID 939). Ensure your local files are readable by this user.

## Tips

1. **Use debug logging**: The dev config enables debug logging by default
2. **Browser DevTools**: Keep console open to catch JavaScript errors
3. **Hot reload**: Consider using browser extensions like LiveReload for auto-refresh
4. **Version control**: The dev scripts are in `.gitignore`, so they won't be committed

## Differences from Production

The development setup differs from production in several ways:

- Debug logging enabled
- Relaxed security settings (anonymous CIDR: *)
- No TLS certificate validation
- Single container (vs. distributed deployment)
- Local file mounts for live editing

## Contributing

When your changes are ready:

1. Test thoroughly in the development environment
2. Run the test suite: `go test ./...`
3. Build a production image to verify: `docker build -t test .`
4. Submit a pull request with your changes

## Legacy Development (Native)

The original `socdev.sh` script runs SOC natively on your host. This approach is more complex but offers maximum flexibility. Use this if you need to:

- Debug with local tools (delve, pprof)
- Make frequent backend changes
- Access raw system resources
- Integrate with local development tools

For most frontend development, the Docker-based approaches are recommended.