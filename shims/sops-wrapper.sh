#!/usr/bin/env bash
#
# Best-effort SopsHQ usage reporter (Linux/macOS).
#
# Install it as a "sops" wrapper that sits EARLIER on PATH than the real sops. Every
# likely-decrypt invocation is reported to the SopsHQ panel's ingestion endpoint
# (fire-and-forget, never blocking sops), then the REAL sops runs unchanged.
#
# BEST-EFFORT and bypassable: someone can call the real binary directly or use the
# key in their own code. It exists for visibility, not enforcement. Run it as the
# normal user (NOT sudo) - decrypt needs that user's own key store.
#
# Finding the real sops: set SOPSHQ_REAL_SOPS to its path, OR leave it unset and the
# wrapper auto-discovers the next sops on PATH that is not itself (so you can either
# rename the real binary to sops.real, or just place this wrapper earlier on PATH).
#
# System-wide install (needs sudo once):
#   sudo mv /usr/local/bin/sops /usr/local/bin/sops.real
#   sudo install -m 0755 sops-wrapper.sh /usr/local/bin/sops
# Per-user install (NO sudo): put this earlier on your PATH as ~/bin/sops, chmod +x.
# Then set:
#   export SOPSHQ_PANEL_URL=http://127.0.0.1:8770
#   export SOPSHQ_INGEST_TOKEN_FILE=/path/to/sopshq/data/ingest.token
#   # SOPSHQ_REAL_SOPS optional (auto-discovered if unset)

set -u

# Resolve the real sops binary. An explicit SOPSHQ_REAL_SOPS wins; otherwise
# auto-discover the next sops/sops.real on PATH that is not this wrapper.
# Prints the real sops path on stdout and returns 0; on failure writes a clear
# message to stderr and returns non-zero. It must RETURN (not exit): it runs inside
# a command substitution, where exit would only end the subshell and let the script
# fall through to an empty exec.
resolve_real_sops() {
    if [ -n "${SOPSHQ_REAL_SOPS:-}" ]; then
        if [ -x "$SOPSHQ_REAL_SOPS" ]; then
            printf '%s' "$SOPSHQ_REAL_SOPS"
            return 0
        fi
        echo "sops-wrapper: SOPSHQ_REAL_SOPS='$SOPSHQ_REAL_SOPS' is not executable." >&2
        return 2
    fi
    local self candidate resolved
    self="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    # type -aP lists every executable named NAME on PATH (one per line). Take the
    # first that is not this wrapper.
    for name in sops.real sops; do
        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            resolved="$(readlink -f "$candidate" 2>/dev/null || echo "$candidate")"
            [ "$resolved" = "$self" ] && continue   # never call ourselves
            if [ -x "$resolved" ]; then
                printf '%s' "$resolved"
                return 0
            fi
        done < <(type -aP "$name" 2>/dev/null)
    done
    echo "sops-wrapper: cannot find the real sops. Install sops, or set SOPSHQ_REAL_SOPS to its path." >&2
    return 2
}

REAL_SOPS="$(resolve_real_sops)" || exit 2
PANEL_URL="${SOPSHQ_PANEL_URL:-http://127.0.0.1:8770}"
TOKEN_FILE="${SOPSHQ_INGEST_TOKEN_FILE:-$HOME/.config/sopshq/ingest.token}"

report() {
    # Skip clearly non-decrypt operations (encrypt / rekey).
    for a in "$@"; do
        case "$a" in
            -e|--encrypt|updatekeys) return 0 ;;
        esac
    done
    [ -r "$TOKEN_FILE" ] || return 0
    local token path=""
    token="$(tr -d '[:space:]' < "$TOKEN_FILE" 2>/dev/null)"
    [ -n "$token" ] || return 0
    # Best-effort: the last argument is usually the target file.
    for a in "$@"; do path="$a"; done
    # Minimal JSON escaping for backslash and double-quote.
    path="${path//\\/\\\\}"
    path="${path//\"/\\\"}"
    curl -fsS -m 2 -X POST "$PANEL_URL/ingest/keyused" \
        -H "X-SopsHQ-Token: $token" -H "Content-Type: application/json" \
        --data "{\"user\":\"${USER:-unknown}\",\"path\":\"$path\",\"source\":\"sops-shim\"}" \
        >/dev/null 2>&1 || true
}

# Report in the background so sops is never delayed, then run the real sops.
report "$@" &
exec "$REAL_SOPS" "$@"
