# Three-tier SPC demo: browser ↔ merchant front ↔ merchant back ↔ bank/ACS

Extends the [two-origin demo](../two-origin/README.md) with a real
**merchant backend** between the shopper's browser and the bank/ACS. This
is the production posture: the browser only talks to the merchant, and
the merchant talks to the bank server-to-server (no CORS, no client
involvement) — the "back channel" you asked about.

| Port | Role | Notes |
|---|---|---|
| `8001` | FakeBank — RP + ACS | Reused as-is from `two-origin/bank/`. |
| `8003` | Merchant backend (relay) | Receives the browser POSTs, talks to the bank over `file_get_contents()` server-to-server. Stores assertions as PENDING and resolves them lazily on a /status poll. |
| `8002` | Merchant frontend (static) | Browser-side checkout. Polls `/api/payment/status` until the bank's verdict arrives. |

## Run it

```bash
cd docs/examples/spc-demo
./three-tier/run.sh
```

Open in Chromium, in order:

1. **<http://localhost:8001/register.html>** — enrol a credential at FakeBank
2. **<http://localhost:8002/checkout.html>** — pay

## Flow

```
Browser (merchant-front, 8002)
   │
   │  1. POST /api/payment/options                                 (CORS)
   ▼
Merchant backend (8003)
   │  2. POST http://localhost:8001/api/payment/options            (server-to-server)
   ▼
Bank/ACS (8001)
   │ ◀── { rpId, challenge, credentialIds, instrument, … }
Merchant backend
   │ ◀── (relays unchanged)
Browser
   │  3. PaymentRequest.show() — user signs in the SPC dialog
   │
   │  4. POST /api/payment/submit  { transactionId, credential }   (CORS)
   ▼
Merchant backend
   │  - parks the assertion as PENDING in TransactionStore
   │  - returns IMMEDIATELY: { status: "PENDING", pollEverySeconds: 1 }
   │
Browser
   │  5. GET /api/payment/status?txn=ORD-…                          (CORS, polled every 1s)
   ▼
Merchant backend
   │  - if PENDING and >= 2s old:
   │      POST http://localhost:8001/api/acs/verify                 (server-to-server, the ACTUAL bank verify)
   │      ↳ on success: store APPROVED + bankResponse
   │      ↳ on failure: store DECLINED + error
   │  - returns the current status
Browser
   │  ▶ keeps polling until status flips to APPROVED / DECLINED
```

The 2-second `BACK_CHANNEL_DELAY_SECONDS` constant in
`merchant-back/router.php` simulates a real back-channel that goes through
the card network. Set it to 0 for instant verify, or higher to make the
polling visible in the UI logs.

## What this matches in real EMV 3DS

| Three-tier step | EMV 3DS message |
|---|---|
| Browser POST `/api/payment/options` to merchant backend | Browser SDK calls merchant's `/start-payment` |
| Merchant backend → bank `/api/payment/options` | 3DS Server `PReq` (preparation) preparing SPC parameters |
| Browser POST `/api/payment/submit` with WebAuthn artefacts | Merchant collects SPC result client-side |
| Merchant backend POST `/api/acs/verify` (the back channel) | 3DS Server `AReq` over the card network → ACS |
| Bank ACS returns APPROVED + ARes JSON | ACS `ARes` over the card network → 3DS Server |
| Browser polling `GET /api/payment/status` | Out-of-band / polling pattern (EMV 3DS v2.3 §6.6 OOB), or the merchant simply waits server-side and pushes back via WebSocket / SSE |

## Why no real worker / queue

PHP's built-in server is single-process so we cannot truly background-process
the bank verify. The lazy-on-poll trick gives the same perceived behaviour
without needing Beanstalkd / Symfony Messenger / etc. In production the
merchant backend would:

- accept the assertion synchronously, return PENDING + 202;
- enqueue a job (Symfony Messenger, Resque, a webhook to the PSP);
- mark the transaction APPROVED when the worker / webhook completes;
- push the verdict to the browser via WebSocket, SSE, or have the browser
  poll exactly as in this demo.
