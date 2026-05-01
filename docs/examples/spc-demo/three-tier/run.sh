#!/usr/bin/env bash
#
# Boot the three-tier SPC demo:
#   - FakeBank (RP + ACS)             on http://localhost:8001
#   - FakeMerchant backend (relay)    on http://localhost:8003
#   - FakeMerchant frontend (static)  on http://localhost:8002
#
# Usage:  ./three-tier/run.sh   (from docs/examples/spc-demo/)

set -e

cd "$(dirname "$0")/.."

if [[ ! -d vendor ]]; then
    echo "▶ vendor/ missing — running composer install"
    composer install --no-interaction
fi

BANK_PORT=8001
FRONT_PORT=8002
BACK_PORT=8003

is_busy() { lsof -i ":$1" >/dev/null 2>&1 || ss -ltn 2>/dev/null | grep -q ":$1 "; }
for p in "$BANK_PORT" "$FRONT_PORT" "$BACK_PORT"; do
    if is_busy "$p"; then
        echo "✗ Port $p already in use. Free it and retry." >&2
        exit 1
    fi
done

cleanup() {
    echo
    echo "▶ Stopping servers…"
    [[ -n "${BANK_PID:-}" ]] && kill "$BANK_PID" 2>/dev/null || true
    [[ -n "${BACK_PID:-}" ]] && kill "$BACK_PID" 2>/dev/null || true
    [[ -n "${FRONT_PID:-}" ]] && kill "$FRONT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "▶ FakeBank             → http://localhost:$BANK_PORT"
echo "▶ Merchant backend     → http://localhost:$BACK_PORT"
echo "▶ Merchant frontend    → http://localhost:$FRONT_PORT"
echo
echo "Steps:"
echo "  1. open http://localhost:$BANK_PORT/register.html  (enrol once)"
echo "  2. open http://localhost:$FRONT_PORT/checkout.html (pay)"
echo
echo "Logs follow. Ctrl+C to stop."
echo "──────────────────────────────────────────────────────"

php -S "localhost:$BANK_PORT" -t two-origin/bank/public two-origin/bank/router.php 2>&1 \
    | sed -u 's/^/[bank]      /' &
BANK_PID=$!

php -S "localhost:$BACK_PORT" -t three-tier/merchant-back three-tier/merchant-back/router.php 2>&1 \
    | sed -u 's/^/[mer-back]  /' &
BACK_PID=$!

php -S "localhost:$FRONT_PORT" -t three-tier/merchant-front/public 2>&1 \
    | sed -u 's/^/[mer-front] /' &
FRONT_PID=$!

wait
