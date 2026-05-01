# SPC Demo — `web-auth/webauthn-lib`

A minimal end-to-end demo of W3C [Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/),
following the same shape as the Chrome developer guides for
[register](https://developer.chrome.com/docs/payments/register-secure-payment-confirmation)
and [authenticate](https://developer.chrome.com/docs/payments/authenticate-secure-payment-confirmation).

Three flavours, in order of increasing realism:

- **Same-origin** (the rest of this README) — one server hosts both the
  merchant page and the relying-party API. Quickest to read.
- **[Two-origin](two-origin/README.md)** — split into a separate
  `bank` server (RP + 3DS ACS, port 8001) and `merchant` server (static
  checkout, port 8002), with cross-origin POSTs and CORS, mirroring the
  EMV 3DS SPC Authentication shape.
- **[Three-tier](three-tier/README.md)** — adds a real `merchant backend`
  (port 8003) between the browser and the bank. The browser only talks to
  the merchant; the merchant talks to the bank server-to-server (back
  channel). The browser polls a status endpoint until the bank has
  answered — the production posture for an asynchronous 3DS2 flow.

## What it demonstrates

- **Registration** — the relying party page calls
  `navigator.credentials.create({ publicKey: { …, extensions: { payment: { isPayment: true } } } })`,
  the server validates with `AuthenticatorAttestationResponseValidator`, and
  the credential is stored.
- **Payment authentication** — the merchant page calls
  `new PaymentRequest([{ supportedMethods: 'secure-payment-confirmation', data: {…} }]).show()`.
  The browser shows its own SPC dialog (amount, payee, instrument). On confirm
  the relying party server validates the assertion. The signed
  `clientDataJSON.payment` is checked field-by-field against the original
  request via `PaymentClientDataCollector`, and the
  `clientExtensionResults.payment.browserBoundSignature` structural check
  is performed by `PaymentExtensionOutputChecker`.

```
┌──────────────────┐     POST /api/register/options      ┌────────────────────┐
│  register.html   │ ──────────────────────────────────▶ │  router.php (RP)   │
│  (browser)       │ ◀────────── creation options ────── │  - lib + serializer│
│                  │                                     │  - CredentialStore │
│  navigator.      │     POST /api/register/verify       │  - PaymentClient-  │
│  credentials     │ ──────────────────────────────────▶ │    DataCollector   │
│  .create({…,     │                                     │                    │
│   payment:       │                                     │                    │
│   {isPayment:    │                                     │                    │
│    true}})       │                                     │                    │
└──────────────────┘                                     └────────────────────┘

┌──────────────────┐     POST /api/payment/options       ┌────────────────────┐
│  checkout.html   │ ──────────────────────────────────▶ │  router.php        │
│  (browser)       │ ◀── challenge + credentialIds ───── │                    │
│                  │                                     │  Stash request     │
│  PaymentRequest( │                                     │  options keyed by  │
│   [{supported-   │                                     │  challenge.        │
│    Methods:      │                                     │                    │
│    'secure-      │     POST /api/payment/verify        │                    │
│    payment-      │ ──────────────────────────────────▶ │  AuthenticatorAss- │
│    confirmation',│                                     │  ertionResponse-   │
│    data: {…}}]). │                                     │  Validator->check  │
│   show()         │                                     │   → collector +    │
└──────────────────┘                                     │     output checker │
                                                         └────────────────────┘
```

## Run it

```bash
cd docs/examples/spc-demo
./same-origin/run.sh
```

The script `composer install`s on first run and boots the demo on
<http://localhost:8000>. The shipped `composer.json` symlinks
`web-auth/webauthn-framework` from this checkout (`../../..`), so you get
the not-yet-released SPC code straight from `src/`. To run against a
published `^5.4` release once one exists, swap the path-repo block for
the standard packagist `web-auth/webauthn-lib` requirement.

Open <http://localhost:8000> in a Chromium-based browser. SPC requires:

- A platform authenticator (Touch ID, Windows Hello, Android device unlock).
- A secure context. `localhost` qualifies; otherwise serve over HTTPS.
- Chrome 105+ / Edge 105+ / Opera 91+.

Walk through the two pages in order:

1. <http://localhost:8000/register.html> — register a credential.
2. <http://localhost:8000/checkout.html> — pay with SPC.

State (registered credentials, in-flight challenges) lives in a JSON file at
`var/credentials.json` and the PHP session.

## After verification — what to do with the result

SPC is a **proof of authorization**, not a payment rail. The relying party
server's `->check()` confirms cryptographically that the cardholder saw and
approved exactly the displayed transaction. Moving money still goes through
the merchant's existing PSP / card network / ACH flow; you forward the
WebAuthn artefacts as the SCA evidence.

After the demo's `/api/payment/verify` succeeds you get back:

| Field | What it is |
|---|---|
| `clientDataType` | `"payment.get"` for SPC, `"webauthn.get"` for a plain WebAuthn assertion. |
| `signCount` | The credential's updated authenticator counter. Persist it. |
| `userVerified` / `userPresent` | UV/UP bits — proof of biometric / device unlock. |
| `signedPayment` | The exact `CollectedClientAdditionalPaymentData` the user signed (rpId, topOrigin, total, instrument, payee*). Compare to what was shown in the SPC dialog — they must match. |
| `artefactsForIssuer.{credentialId,clientDataJSON,authenticatorData,signature,userHandle}` | Base64url-encoded raw bytes the issuer / 3DS ACS needs to re-verify the assertion. |

In a real integration these artefacts plug into [EMV 3-D Secure
v2.3.1.1 §6.1.4.1.5 "SPC Authentication"](https://www.emvco.com/specifications/):
the merchant PSP submits them in the `AReq` to the issuer's ACS (which holds
the credential's public key from enrollment) and the ACS re-verifies the
WebAuthn signature, returning a Frictionless authorization with full
liability shift.

## Linking the SPC authorisation back to your order

W3C SPC does not define a "merchant reference" field — the user only signs
`rpId / topOrigin / total / instrument / payee*`. The standard FIDO2 way to
correlate the authorisation with your business object (order id, cart id,
invoice number…) is to **bind it server-side to the WebAuthn challenge**.
The challenge is a unique nonce that the authenticator signs, so whatever
you map to it in your DB cannot be tampered with.

The demo does this:

```php
// /api/payment/options
$challenge = random_bytes(32);
$_SESSION['spc_txn'][base64url($challenge)] = $transactionId; // ← bind

// /api/payment/verify
$challenge = $response->clientDataJSON->challenge;
$transactionId = $_SESSION['spc_txn'][base64url($challenge)]; // ← recover
```

The merchant frontend posts a `transactionId` to `/api/payment/options`,
gets it back in the response (so it knows which order the challenge is for),
and the same id is echoed by `/api/payment/verify` once the authenticator
proof has been validated. In production replace the session map with a row
in your orders table keyed by the challenge (or by your own UUID with the
challenge as a column).

## Same endpoint accepts plain WebAuthn assertions too

The demo wires both `WebauthnAuthenticationCollector` (for `webauthn.get`)
and `PaymentClientDataCollector` (for `payment.get`) into the
`ClientDataCollectorManager`. The same `/api/payment/verify` endpoint
therefore accepts:

- a credential produced by the SPC `PaymentRequest.show()` flow
  (`clientDataJSON.type === "payment.get"`), validated via the payment
  collector;
- a credential produced by a regular `navigator.credentials.get()` call
  (`clientDataJSON.type === "webauthn.get"`), validated via the standard
  WebAuthn collector.

This mirrors the SimpleWebAuthn server pattern of accepting
`expectedType: ['webauthn.get', 'payment.get']` on a single verify route.

## A note on `payeeOrigin`

The SPC `payeeOrigin` field must be a valid HTTPS URL — `http://localhost`
is rejected even when the page itself is a secure context. The demo passes
a fixed `https://demo-merchant.example` value to satisfy this constraint;
the browser displays it inside the SPC confirmation dialog but never
networks to it. Replace it with your real merchant origin in production.

## Cross-origin (real merchant + RP)

The Chrome guides emphasise the cross-origin shape: the merchant runs at
`merchant.example`, the relying party (issuing bank, PSP) runs at `rp.example`,
and SPC works because the browser dialog references the relying party's
credential. To replicate that with this demo:

- Run the demo as the relying party at `https://rp.localhost`.
- Build a tiny merchant page at `https://merchant.localhost` that posts
  `POST /api/payment/options` to the RP (with CORS), takes the response, and
  calls `PaymentRequest.show()` on its own origin. The `payeeOrigin` it sends
  to the user agent must match its own origin.
- The merchant POSTs the resulting `PaymentResponse.details` back to the RP's
  `/api/payment/verify` endpoint, again with CORS.

The same `PaymentClientDataCollector` validation runs on the RP side — it
compares the signed `clientDataJSON.payment` to the request options it
issued, so the merchant cannot tamper with the amount the user signs.

## What this demo deliberately leaves out

- Cross-origin headers (CORS, Permissions-Policy `payment=*`).
- A real database / user system (uses a JSON file).
- `BrowserBoundSignature` cryptographic verification — the lib's checker
  asserts the signature is structurally present; verifying it cryptographically
  requires storing the registration-time `BrowserBoundPublicKey`, which
  is left to the relying party.
- Account recovery / multi-credential UI.
