#!/usr/bin/env bash
set -euo pipefail

# Build both the library and example daemon
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."

cd "${ROOT_DIR}"
cargo build --workspace

echo "Build complete. Binaries are in target/debug/"
