# Two-origin SPC demo: merchant ↔ bank/ACS

Splits the same-origin demo into the two real roles of an EMV 3DS SPC
Authentication exchange:

| Origin | Role | Endpoints |
|---|---|---|
| `http://localhost:8001` (FakeBank) | Relying party + 3DS ACS — holds credential public keys | `POST /api/register/{options,verify}`, `POST /api/payment/options`, `POST /api/acs/verify` |
| `http://localhost:8002` (FakeMerchant) | Merchant — only serves static HTML, never sees private keys | (no API; the frontend POSTs cross-origin to FakeBank) |

Both origins share `rpId: localhost`, so a credential enrolled on
`localhost:8001` is usable from `localhost:8002` — the same condition that
holds for a real `bank.example` ↔ `merchant.example` pair sharing the
issuer's RP id.

## Run it

```bash
cd docs/examples/spc-demo
./two-origin/run.sh
```

The script `composer install`s on first run, boots both servers with
prefixed logs (`[bank]` / `[merchant]`) and cleans up on Ctrl+C. To run
the servers manually instead:

```bash
php -S localhost:8001 -t two-origin/bank/public two-origin/bank/router.php &
php -S localhost:8002 -t two-origin/merchant/public &
```

Then in a Chromium browser:

1. Open <http://localhost:8001/register.html> and enrol a credential
   (your platform authenticator unlocks).
2. Open <http://localhost:8002/checkout.html> and click "Pay". The
   merchant calls cross-origin to the bank, the SPC dialog opens, you
   confirm, the bank's ACS verifies and returns a 3DS-style ARes.

## Flow

```
Browser (FakeMerchant page http://localhost:8002)
    │
    │ 1. fetch('/api/payment/options') — CORS POST cross-origin
    ▼
Bank server http://localhost:8001
    │  - looks up credentialIds for the cardholder
    │  - generates challenge, builds PaymentExtension::authenticate(...)
    │  - stashes {challenge → transactionId, userHandle, requestOptions}
    │
    │ ◀── { rpId, challenge, credentialIds, instrument, payeeName, … }
    │
Browser
    │ 2. new PaymentRequest([{ supportedMethods: 'secure-payment-confirmation',
    │                          data: {…} }]).show()
    │
    │    User agent shows the SPC dialog using the bank-issued payment data,
    │    user authenticates locally, browser signs clientDataJSON+authData.
    │
    │ 3. fetch('/api/acs/verify') — CORS POST cross-origin
    ▼
Bank server http://localhost:8001 (ACS role)
    │  - looks up the stashed requestOptions by challenge
    │  - looks up the credential's public key by credentialId
    │  - AuthenticatorAssertionResponseValidator->check(...) :
    │      • verifies signature with the public key                  ←── the math
    │      • PaymentClientDataCollector compares clientData.payment
    │        to the stashed requestOptions.payment input             ←── tamper check
    │      • PaymentExtensionOutputChecker on browserBoundSignature
    │      • CheckOrigin allows http://localhost:8002 (merchant origin)
    │  - on success: returns mock 3DS ARes
    │
    │ ◀── { transStatus: "Y", eci: "05", authenticationValue: "<CAVV>", … }
    │
Browser  ← merchant displays the ARes / proceeds to capture the payment
```

## Mapping to real EMV 3DS SPC Authentication

| Demo step | EMV 3DS message |
|---|---|
| Merchant POST `/api/payment/options` | Merchant → 3DS Server (server-side prep, no on-wire equivalent) |
| Bank → merchant `{challenge, credentialIds, …}` | Issuer ACS → DS → 3DS Server `CReq` parameters |
| `PaymentRequest.show()` + sign | EMV 3DS SPC Authentication ceremony at the cardholder browser |
| Merchant POST `/api/acs/verify` with the WebAuthn artefacts | 3DS Server → DS → ACS `AReq` carrying the SPC parameters |
| Bank verify + ARes JSON (`transStatus=Y`, `eci=05`, `CAVV`) | ACS → DS → 3DS Server `ARes` |

Real production hops travel over the card network (Visa Directory Server,
Mastercard Directory Server, CB, …) instead of a direct cross-origin
fetch — that is the only thing the two-origin demo glosses over.

## Why no `bank.example` / `merchant.example` hostnames

Chrome treats every `localhost:N` origin as a secure context, so SPC works
straight from `php -S` without TLS or `/etc/hosts` entries. To use real
hostnames you need:

- `127.0.0.1 bank.localhost merchant.localhost` (or another DNS) in
  `/etc/hosts` plus mkcert-issued certs and a reverse-proxy (Caddy /
  nginx) terminating TLS.
- Set `rpId` to the registrable suffix shared by both, e.g. `localhost`.
