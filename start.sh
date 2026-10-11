#!/usr/bin/env bash
#
# start.sh - launch SopsHQ from SOURCE for development (no build step).
#
# `go run` compiles fresh from the current source and serves in the FOREGROUND
# (Ctrl-C to stop), so you always run the LATEST code without building a binary.
# The HTML/CSS/JS are embedded at compile time; the version is injected from the
# VERSION file so the panel footer shows the real number (not "dev").
#
# For running a COMPILED binary in the background with a PID file (a server/deploy
# install), use `sopshq start` and `sopshq stop` instead.
#
# The vault key is read interactively (or from SOPSHQ_VAULT_KEY). The
# config + data location is auto-discovered (the pointer under your user config dir),
# so an existing install is found automatically.
#
# Usage:
#   ./start.sh                 # auto-discover config, prompt for vault key
#   ./start.sh -config PATH    # use a specific config file
#   SOPSHQ_VAULT_KEY=... ./start.sh   # non-interactive unlock
#
# Stop with Ctrl-C.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
  echo "start.sh: Go is not on PATH; install Go to run SopsHQ from source" >&2
  echo "          (or run a prebuilt binary with \`sopshq start\`)." >&2
  exit 1
fi

version="$(tr -d '[:space:]' < VERSION 2>/dev/null || echo dev)"

echo "Starting SopsHQ ${version} from source (Ctrl-C to stop)..."
exec go run -ldflags "-X main.version=${version}" ./cmd/sopshq serve "$@"
