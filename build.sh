#!/usr/bin/env bash
#
# SopsHQ build script. Compiles the linux/amd64 and windows/amd64 binaries into
# dist/, with the version injected from the single-source-of-truth VERSION file.
#
#   ./build.sh           build both binaries (fast - compile only, no tests)
#   ./build.sh --check   run `go vet` + `go test ./...` first, then build
#
# Compiling is what a build does; the test suite (its slow part is the deliberate
# PBKDF2 work factor) runs in CI and on demand via --check, not on every deploy build.
#
# CGO is disabled (the project is pure stdlib plus rsc.io/qr), so the binaries are
# static and cross-compile cleanly from any host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
LDFLAGS="-s -w -X main.version=$VERSION"   # -s -w strip debug info (smaller binaries)

echo "=== SopsHQ build (version $VERSION) ==="

if [ "${1:-}" = "--check" ]; then
    echo "-> go vet ./..."
    go vet ./...
    echo "-> go test ./..."
    go test ./...
fi

mkdir -p dist

echo "-> building linux/amd64   -> dist/sopshq"
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/sopshq     ./cmd/sopshq

echo "-> building windows/amd64 -> dist/sopshq.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o dist/sopshq.exe ./cmd/sopshq

# dist/ holds just the binary: background run/stop is built in (`sopshq start` /
# `sopshq stop`) and install (service account + systemd unit) is `sudo ./dist/sopshq
# setup`. A deploy install is a single file.
echo ""
echo "[ok] build complete:"
for f in dist/sopshq dist/sopshq.exe; do
    [ -f "$f" ] && echo "     $(du -h "$f" | cut -f1)  $f"
done
echo ""
echo "  install (root):  sudo ./dist/sopshq setup"
echo "  background run:  ./dist/sopshq start   (stop: ./dist/sopshq stop)"
echo "  dev (no build):  ./start.sh            (foreground, from source)"
echo "  build + tests:   ./build.sh --check"
