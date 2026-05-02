#!/usr/bin/env bash
#
# Boot the same-origin PRF demo on http://localhost:8000.
# Usage:  ./same-origin/run.sh   (from docs/examples/prf-demo/)

set -e

cd "$(dirname "$0")/.."

if [[ ! -d vendor ]]; then
    echo "▶ vendor/ missing — running composer install"
    composer install --no-interaction
fi

PORT=8000

is_busy() { lsof -i ":$1" >/dev/null 2>&1 || ss -ltn 2>/dev/null | grep -q ":$1 "; }
if is_busy "$PORT"; then
    echo "✗ Port $PORT already in use. Free it and retry." >&2
    exit 1
fi

cleanup() {
    echo
    echo "▶ Stopping server…"
    [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "▶ PRF demo (same-origin) → http://localhost:$PORT"
echo
echo "Steps:"
echo "  1. open http://localhost:$PORT/register.html  (register a credential with PRF — online)"
echo "  2. open http://localhost:$PORT/vault.html     (unlock + add/decrypt items — online)"
echo "  3. open http://localhost:$PORT/offline.html   (server-free vault: localStorage + service worker)"
echo
echo "Logs follow. Ctrl+C to stop."
echo "──────────────────────────────────────────────────────"

php -S "localhost:$PORT" -t same-origin/public same-origin/router.php &
PID=$!

wait
