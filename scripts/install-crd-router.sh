#!/usr/bin/env bash
# Clones dflippojr/fhir-crd-router at the pinned commit into .deps/ and installs
# it into the local Maven repository so the workbench build can resolve it.
set -euo pipefail

REPO_URL="${CRD_ROUTER_REPO_URL:-https://github.com/dflippojr/fhir-crd-router.git}"
COMMIT="808abc0abf0427b2a41a5e8c7a88f85430431548"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$root/.deps/fhir-crd-router"

if [ ! -d "$dest/.git" ]; then
  mkdir -p "$root/.deps"
  git clone --quiet "$REPO_URL" "$dest"
fi

git -C "$dest" fetch --quiet origin
git -C "$dest" checkout --quiet --detach "$COMMIT"

cd "$dest"
chmod +x mvnw
./mvnw -q install -DskipTests -DskipITs
echo "Installed fhir-crd-router at $(git rev-parse --short HEAD)"
