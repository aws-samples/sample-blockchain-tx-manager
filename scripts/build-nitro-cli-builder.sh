#!/usr/bin/env bash
# Build the pinned x86_64 Nitro CLI image used to create/measure EIFs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME="${CDK_DOCKER:-finch}"
IMAGE="${NITRO_CLI_BUILDER_IMAGE:-btm-nitro-cli:1.4.4}"
OUTPUT="${NITRO_CLI_BUILDER_TAR:-}"

command -v "$RUNTIME" >/dev/null 2>&1 || {
    echo "Error: container runtime '$RUNTIME' not found (set CDK_DOCKER)." >&2
    exit 1
}

"$RUNTIME" build --platform linux/amd64 \
    -f "$ROOT_DIR/tools/nitro-cli-builder/Dockerfile" \
    -t "$IMAGE" "$ROOT_DIR"

VERSION=$("$RUNTIME" run --rm --platform linux/amd64 "$IMAGE" --version)
[ "$VERSION" = "Nitro CLI 1.4.4" ] || {
    echo "Error: expected Nitro CLI 1.4.4, got: $VERSION" >&2
    exit 1
}

if [ -n "$OUTPUT" ]; then
    mkdir -p "$(dirname "$OUTPUT")"
    "$RUNTIME" save "$IMAGE" -o "$OUTPUT"
    shasum -a 256 "$OUTPUT" > "$OUTPUT.sha256"
    echo "Saved builder: $OUTPUT"
fi

echo "Nitro CLI builder ready: $IMAGE ($VERSION)"
