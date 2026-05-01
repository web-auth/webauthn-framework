#!/usr/bin/env bash
#
# Boot the two-origin SPC demo (FakeBank on 8001, FakeMerchant on 8002).
# Ctrl+C stops both servers cleanly.
#
# Usage:  ./two-origin/run.sh   (from docs/examples/spc-demo/)

set -e

cd "$(dirname "$0")/.."

if [[ ! -d vendor ]]; then
    echo "▶ vendor/ missing — running composer install"
    composer install --no-interaction
fi

BANK_PORT=8001
MERCHANT_PORT=8002

is_busy() { lsof -i ":$1" >/dev/null 2>&1 || ss -ltn 2>/dev/null | grep -q ":$1 "; }
if is_busy "$BANK_PORT" || is_busy "$MERCHANT_PORT"; then
    echo "✗ Port $BANK_PORT or $MERCHANT_PORT already in use. Free them and retry." >&2
    exit 1
fi

cleanup() {
    echo
    echo "▶ Stopping servers…"
    [[ -n "${BANK_PID:-}" ]] && kill "$BANK_PID" 2>/dev/null || true
    [[ -n "${MERCH_PID:-}" ]] && kill "$MERCH_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "▶ FakeBank   → http://localhost:$BANK_PORT"
echo "▶ FakeMerchant → http://localhost:$MERCHANT_PORT"
echo
echo "Steps:"
echo "  1. open http://localhost:$BANK_PORT/register.html  (enrol once)"
echo "  2. open http://localhost:$MERCHANT_PORT/checkout.html  (pay)"
echo
echo "Logs follow. Ctrl+C to stop."
echo "──────────────────────────────────────────────────────"

php -S "localhost:$BANK_PORT" -t two-origin/bank/public two-origin/bank/router.php 2>&1 \
    | sed -u 's/^/[bank]      /' &
BANK_PID=$!

php -S "localhost:$MERCHANT_PORT" -t two-origin/merchant/public 2>&1 \
    | sed -u 's/^/[merchant]  /' &
MERCH_PID=$!

wait
