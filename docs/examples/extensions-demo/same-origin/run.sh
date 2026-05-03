#!/usr/bin/env bash
#
# Boot the same-origin extensions demo on http://localhost:8000.
# Usage:  ./same-origin/run.sh   (from docs/examples/extensions-demo/)

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

echo "▶ Extensions demo (same-origin) → http://localhost:$PORT"
echo
echo "Steps:"
echo "  1. open http://localhost:$PORT/                 (overview)"
echo "  2. open http://localhost:$PORT/register.html    (register with credProps + credProtect + credBlob + minPinLength)"
echo "  3. open http://localhost:$PORT/assert.html      (assert + retrieve credBlob via getCredBlob)"
echo
echo "Logs follow. Ctrl+C to stop."
echo "──────────────────────────────────────────────────────"

php -S "localhost:$PORT" -t same-origin/public same-origin/router.php &
PID=$!

wait
