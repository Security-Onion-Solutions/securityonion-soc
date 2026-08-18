#!/usr/bin/env bash
#
# Push this branch's SOC web assets into a running so-soc container for testing,
# without building or replacing the image.
#
# Why this shape:
#
#   SOC 3.x serves its UI from /opt/sensoroni/html *inside the image*. Unlike 2.4,
#   /opt/so/html on the host is not bind-mounted into the container, so rsyncing
#   there (what mikebuild.sh --html did) writes somewhere the container never reads.
#   The files are therefore copied straight into the running container.
#
#   web/host.go serves them with http.FileServer(http.Dir(...)), i.e. read from disk
#   per request, so a copy takes effect on the next browser load. Do NOT restart soc
#   to "apply" changes — restarting is how you remove them.
#
# Backing out:
#
#   so-soc-restart runs `docker rm so-soc` and re-applies the salt state, recreating
#   the container from the pristine image. Nothing on the host is modified by this
#   script, so that single command reverts everything:
#
#       ./sodeploy.sh --revert
#
# Usage:
#   ./sodeploy.sh [--host <host>] [--user <user>] [--dry-run] [--revert] [--status]
set -euo pipefail

HOST="${SO_HOST:-somn24}"
USER_NAME="${SO_USER:-mreeves}"
CONTAINER="so-soc"
CONTAINER_HTML="/opt/sensoroni/html"
DRY_RUN=0
ACTION="deploy"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)    HOST="$2"; shift 2 ;;
    --user)    USER_NAME="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --revert)  ACTION="revert"; shift ;;
    --status)  ACTION="status"; shift ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH="ssh -o BatchMode=yes ${USER_NAME}@${HOST}"

run_remote() { $SSH "$@"; }

case "$ACTION" in
  status)
    run_remote 'echo "grid version: $(cat /etc/soversion 2>/dev/null)"; \
      sudo docker ps --filter name=so-soc --format "container: {{.Names}} {{.Image}} ({{.Status}})"; \
      echo "modified html files still in container:"; \
      sudo docker diff so-soc 2>/dev/null | grep "/opt/sensoroni/html" || echo "  (none — container matches its image)"'
    exit 0
    ;;
  revert)
    echo "Reverting: recreating $CONTAINER from its image on $HOST"
    run_remote "sudo so-soc-restart"
    echo "Done. The container now matches the shipped image."
    exit 0
    ;;
esac

# --- deploy ----------------------------------------------------------------

VERSION="$(run_remote 'cat /etc/soversion 2>/dev/null' | tr -d '[:space:]')"
[ -n "$VERSION" ] || { echo "could not read /etc/soversion from $HOST" >&2; exit 1; }
echo "Target $HOST is SOC $VERSION"

# Only files this branch actually changes, and never the jest specs: they are not
# part of the served app and only add noise inside the container.
mapfile -t FILES < <(
  cd "$REPO" && git diff --name-only origin/3/dev...HEAD -- html/ | grep -v '\.test\.js$'
)
[ "${#FILES[@]}" -gt 0 ] || { echo "no changed html files to deploy" >&2; exit 1; }

echo "Deploying ${#FILES[@]} file(s):"
printf '  %s\n' "${FILES[@]}"

if [ "$DRY_RUN" = "1" ]; then
  echo "(dry run — nothing copied)"
  exit 0
fi

# Stage a copy so the version substitution the Dockerfile normally performs at build
# time is applied here too, leaving the working tree untouched.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for f in "${FILES[@]}"; do
  mkdir -p "$STAGE/$(dirname "${f#html/}")"
  cp "$REPO/$f" "$STAGE/${f#html/}"
done
find "$STAGE" -name '*.html' -exec sed -i "s/VERSION_PLACEHOLDER/$VERSION/g" {} +

# Copy via a staging directory on the host, since docker cp runs under sudo there.
REMOTE_TMP="$(run_remote 'mktemp -d')"
tar -C "$STAGE" -czf - . | $SSH "tar -C '$REMOTE_TMP' -xzf -"
run_remote "sudo docker cp '$REMOTE_TMP/.' '${CONTAINER}:${CONTAINER_HTML}/' && rm -rf '$REMOTE_TMP'"

echo
echo "Copied into ${CONTAINER}:${CONTAINER_HTML}."
echo "Hard-refresh the browser (ctrl-shift-R) — no restart is needed, and restarting would undo this."
echo "Enable the page with ?simple-alerts=true, then visit /#/simple-alerts"
echo "Back out with: $0 --revert"
