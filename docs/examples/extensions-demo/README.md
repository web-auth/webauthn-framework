# Authenticator Extensions Demo

A single end-to-end playground that exercises four CTAP / WebAuthn extensions
that `web-auth/webauthn-lib` 5.4 supports out of the box but which were missing
a worked example:

| Extension                       | Spec                | What you'll see                                                                                            |
| ------------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------- |
| `credProps`                     | WebAuthn L3 §10.1.3 | The `rk` flag and (when supported) `authenticatorDisplayName` reported back by the user agent.             |
| `credProtect`                   | CTAP 2.1 §12.1      | The protection policy actually applied by the authenticator, with `enforce` to detect silent downgrades.   |
| `credBlob` / `getCredBlob`      | CTAP 2.1 §12.2      | Up to 32 bytes stored on the authenticator at registration, retrieved during a later assertion.            |
| `minPinLength`                  | CTAP 2.1 §12.4      | The authenticator's configured minimum PIN length (only emitted on the enterprise allow-list — see notes). |

The four are exercised in **a single ceremony** rather than four separate
demos. They overlap conceptually (`credProps.rk` tells you whether your
`credProtect` policy is meaningful), so combining them into one page keeps the
plumbing minimal and lets you toggle each independently to see what changes.

## Run it

From this directory:

```bash
./same-origin/run.sh
```

This installs Composer dependencies (first run only) and starts the PHP
built-in server on `http://localhost:8000`. Then:

1. <http://localhost:8000/> — overview + table of what each extension does.
2. <http://localhost:8000/register.html> — pick a username, optionally pick a
   `credProtect` policy, optionally type a `credBlob` payload (≤32 bytes), and
   register. The server-parsed extension outputs are summarised in a table.
3. <http://localhost:8000/assert.html> — authenticate against a previously
   registered credential. The server uses
   `CredentialBlobAssertionOutput::fromExtensions()` to parse the bytes the
   authenticator returned and compares them with what was stored.

## What the server-side code looks like

All four extensions are attached when building the registration options
(see [`same-origin/router.php`](same-origin/router.php)):

```php
$extensions = [
    CredentialPropertiesInputExtension::enable(),
    MinPinLengthInputExtension::enable(),
];

if ($policy !== null) {
    $extensions[] = CredentialProtectionInputExtension::userVerificationRequired();
    $extensions[] = CredentialProtectionInputExtension::enforce();
}

if ($blob !== '') {
    $extensions[] = CredentialBlobInputExtension::withBlob($blob);
}

$options = PublicKeyCredentialCreationOptions::create(
    rp: PublicKeyCredentialRpEntity::create(...),
    user: PublicKeyCredentialUserEntity::create(...),
    challenge: random_bytes(32),
    pubKeyCredParams: [...],
    attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    extensions: AuthenticationExtensions::create($extensions),
);
```

After validating the attestation, the server reads each extension output via
its typed value object:

```php
$credProps    = CredentialPropertiesOutput::fromExtensions($clientExtensions);
$minPinLength = MinPinLengthOutput::fromExtensions($authenticatorExtensions);
$credProtect  = CredentialProtectionOutput::fromExtensions($authenticatorExtensions);
$credBlobReg  = CredentialBlobRegistrationOutput::fromExtensions($authenticatorExtensions);
```

Note where each one lives:

- `credProps` is a **client** extension (`clientExtensionResults`) — translated
  by the user agent, never by the authenticator.
- `credProtect`, `credBlob`, `minPinLength` are **authenticator** extensions
  (`authData.extensions`) — emitted by the authenticator itself.

## Notes & caveats

- **Browser support varies.** As of mid-2026, Chrome on Android/Linux honours
  `credProtect` and `credBlob` end-to-end. Safari ignores most of these.
  Firefox is in-between. The demo gracefully reports `absent` for any
  extension the authenticator did not return.
- **`minPinLength` is gated on the enterprise allow-list** of the authenticator.
  If your authenticator firmware does not have `localhost` (or your RP id)
  whitelisted, the response will be absent — that is a feature of the spec,
  not a demo bug.
- **`credProtect` + `enforce`**: with `enforce: true`, an authenticator that
  does not implement `credProtect` will fail registration outright instead of
  silently downgrading. The applied-policy column in the result table lets you
  spot a downgrade if you remove `enforce`.
- **Demo storage** is a JSON file under `var/credentials.json` — persistent
  across `./run.sh` invocations but trivially resettable (just delete the
  file). Production code MUST go through
  `Webauthn\CredentialRecordRepositoryInterface`.
- **No HTTPS.** The same-origin demo runs on plain HTTP because
  `localhost` is a [secure context](https://w3c.github.io/webappsec-secure-contexts/#localhost)
  for WebAuthn purposes. Do not deploy this demo behind anything other than a
  fresh `php -S` on your laptop.

## Spec references

- WebAuthn L3 §10.1.3 — Credential Properties
  <https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension>
- CTAP 2.1 §12.1 — `credProtect`
  <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension>
- CTAP 2.1 §12.2 — `credBlob`
  <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credBlob-extension>
- CTAP 2.1 §12.4 — `minPinLength`
  <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension>
