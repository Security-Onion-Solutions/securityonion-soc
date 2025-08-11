# Docker-based SOC Development

This provides a Docker-based alternative to running SOC natively for development.

## Overview

The Docker development workflow uses two terminals:
1. **Terminal 1**: Sets up the remote VM and maintains SSH tunnel
2. **Terminal 2**: Runs SOC in a local Docker container

## Prerequisites

- Docker installed locally
- SSH access to a Security Onion manager VM
- `jq` command-line tool

## Usage

### Terminal 1: Setup VM and SSH Tunnel

```bash
./socdev-docker.sh --manager-ip 192.168.95.59
```

This script:
- Stops the remote SOC container
- Opens necessary firewall ports
- Fetches the remote configuration
- Creates a development configuration
- Sets up SSH reverse port forwarding
- Blocks waiting for Ctrl+C

### Terminal 2: Run SOC in Docker

Once Terminal 1 shows the SSH tunnel is ready:

```bash
./run-soc-docker.sh
```

This script:
- Builds the Docker image if needed
- Starts SOC in a Docker container
- Mounts local directories for live editing
- Follows the container logs

## Access SOC

Access SOC at: `https://<manager-ip>:9822`

The SSH reverse tunnel forwards traffic from the manager VM to your local Docker container.

## Live Editing

- **HTML/JavaScript**: Edit files in `./html/` - changes are reflected immediately
- **Backend (Go)**: Requires rebuilding the Docker image and restarting

## Stopping Development

1. **Terminal 2**: Press Ctrl+C to stop following logs (container keeps running)
2. **Terminal 1**: Press Ctrl+C to close SSH tunnel and restore remote VM

## Cleanup

To restore the remote VM without running the tunnel:

```bash
./socdev-docker.sh --cleanup
```

## Comparison with Native Development

| Feature | Native (socdev.sh) | Docker (socdev-docker.sh) |
|---------|-------------------|---------------------------|
| Setup | Complex (sshfs mounts) | Simple (Docker only) |
| Performance | Faster | Slightly slower |
| Dependencies | Go, npm, etc. | Docker only |
| Live Backend Edits | Yes | No (requires rebuild) |
| Live Frontend Edits | Yes | Yes |

## Troubleshooting

### Container exits immediately

Check logs:
```bash
docker logs soc-dev
```

Common issues:
- Missing required files/directories
- Configuration errors
- Binary not found

### SSH tunnel issues

Ensure you have SSH key access:
```bash
ssh-copy-id onion@<manager-ip>
```

### Build errors

Force rebuild with fresh cache:
```bash
docker build --no-cache -t securityonion-soc:dev .
```