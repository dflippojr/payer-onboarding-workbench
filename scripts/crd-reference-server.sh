#!/usr/bin/env bash
# The HL7 Da Vinci CRD reference server at the commits pinned in
# crd-reference-server.env, in Docker, published on loopback only.
#
#   bash scripts/crd-reference-server.sh image   # build the image unless it exists
#   bash scripts/crd-reference-server.sh start   # image, then run it and wait for discovery
#   bash scripts/crd-reference-server.sh stop    # remove the container (logs first)
#
# CRD_RI_IMAGE_TAR names a docker save file: image loads from it when it exists and
# writes it after a build, so CI can cache the built image by the pinned commits.
# CRD_RI_PORT (default 18090) is the loopback port; the server's base URL is
# http://127.0.0.1:$CRD_RI_PORT/r4.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=crd-reference-server.env
. "$root/scripts/crd-reference-server.env"

image="crd-reference-server:${CRD_COMMIT:0:12}-${CDS_LIBRARY_COMMIT:0:12}"
container="crd-reference-server"
port="${CRD_RI_PORT:-18090}"
tar="${CRD_RI_IMAGE_TAR:-}"

ensure_image() {
  if docker image inspect "$image" > /dev/null 2>&1; then
    echo "Using $image"
    return
  fi
  if [ -n "$tar" ] && [ -f "$tar" ]; then
    docker load --input "$tar"
    docker image inspect "$image" > /dev/null && return
  fi
  echo "Building $image (CRD $CRD_COMMIT, CDS-Library $CDS_LIBRARY_COMMIT)"
  docker build --tag "$image" --build-arg "CDS_LIBRARY_COMMIT=$CDS_LIBRARY_COMMIT" \
    --file - "https://github.com/HL7-DaVinci/CRD.git#$CRD_COMMIT" \
    < "$root/scripts/crd-reference-server.Dockerfile"
  if [ -n "$tar" ]; then
    mkdir -p "$(dirname "$tar")"
    docker save --output "$tar" "$image"
  fi
}

stop() {
  if docker container inspect "$container" > /dev/null 2>&1; then
    docker logs "$container" > "$root/.crd-ri/server.log" 2>&1 || true
    docker rm --force "$container" > /dev/null
    echo "Stopped $container (log in .crd-ri/server.log)"
  fi
}

start() {
  ensure_image
  mkdir -p "$root/.crd-ri"
  stop
  docker run --detach --name "$container" --publish "127.0.0.1:$port:8090" "$image" > /dev/null
  local url="http://127.0.0.1:$port/r4/cds-services"
  for _ in $(seq 1 90); do
    if curl --silent --fail --max-time 5 "$url" > /dev/null; then
      echo "CRD reference server is up: $url"
      return
    fi
    if [ "$(docker container inspect --format '{{.State.Running}}' "$container")" != true ]; then
      break
    fi
    sleep 2
  done
  echo "CRD reference server did not answer $url" >&2
  docker logs --tail 80 "$container" >&2 || true
  exit 1
}

case "${1:-}" in
  image) ensure_image ;;
  start) start ;;
  stop) mkdir -p "$root/.crd-ri"; stop ;;
  *) echo "usage: $0 image|start|stop" >&2; exit 2 ;;
esac
