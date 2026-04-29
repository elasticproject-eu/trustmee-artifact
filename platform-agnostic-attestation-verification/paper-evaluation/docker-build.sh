#!/usr/bin/env bash
# One-shot: build the paper-evaluation docker image.
# Run from inside `paper-evaluation/`:
#   bash docker-build.sh
# or from the repo parent:
#   bash platform-agnostic-attestation-verification/paper-evaluation/docker-build.sh
set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$THIS_DIR/../.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-trustmee-paper-eval}"

docker build \
  --platform="${DOCKER_PLATFORM:-linux/amd64}" \
  -f "$THIS_DIR/Dockerfile" \
  -t "$IMAGE_TAG" \
  "$WORKSPACE_ROOT"

echo "image: $IMAGE_TAG"
