#!/usr/bin/env bash
# One-shot: run the paper-evaluation inside docker, mounting results/ outside.
#   bash docker-run.sh
#   bash docker-run.sh --network-overhead
#   bash docker-run.sh --more-detail
set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-trustmee-paper-eval}"
NETWORK_OVERHEAD="${NETWORK_OVERHEAD:-0}"
MORE_DETAIL="${MORE_DETAIL:-0}"

usage() {
  cat <<'EOF'
Usage: bash docker-run.sh [--network-overhead] [--more-detail]

Options:
  --network-overhead     Run only eval 7, which measures collateral-fetch network overhead.
  --no-network-overhead  Run the default evals 1 through 6.
  --more-detail          Also generate detailed/secondary figures.
  --no-more-detail       Generate only the default figure set.
  -h, --help             Show this help.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --network-overhead)
      NETWORK_OVERHEAD=1
      ;;
    --network-overhead=*)
      NETWORK_OVERHEAD="${1#*=}"
      ;;
    --no-network-overhead)
      NETWORK_OVERHEAD=0
      ;;
    --more-detail)
      MORE_DETAIL=1
      ;;
    --more-detail=*)
      MORE_DETAIL="${1#*=}"
      ;;
    --no-more-detail)
      MORE_DETAIL=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

mkdir -p "$THIS_DIR/results"

if [[ "${SKIP_DOCKER_BUILD:-0}" != "1" ]]; then
  echo "building/updating image $IMAGE_TAG"
  bash "$THIS_DIR/docker-build.sh"
elif ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "image $IMAGE_TAG not found; building first"
  bash "$THIS_DIR/docker-build.sh"
fi

exec docker run \
  --rm \
  --platform="${DOCKER_PLATFORM:-linux/amd64}" \
  -e RUNS="${RUNS:-50}" \
  -e NETWORK_OVERHEAD="$NETWORK_OVERHEAD" \
  -e MORE_DETAIL="$MORE_DETAIL" \
  -v "$THIS_DIR/results:/work/platform-agnostic-attestation-verification/paper-evaluation/results" \
  "$IMAGE_TAG"
