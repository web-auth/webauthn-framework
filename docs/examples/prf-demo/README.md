# PRF Demo — `web-auth/webauthn-lib`

A minimal end-to-end demo of the W3C [WebAuthn PRF
extension](https://www.w3.org/TR/webauthn-3/#prf-extension) used as a primitive
for **client-side encryption**, inspired by Matt Miller's
[2023 write-up](https://blog.millerti.me/2023/01/22/encrypting-data-in-the-browser-using-webauthn/).

> ## ⚠️ Read this before you build a real product on PRF
>
> Quoting Matt Miller's [May 2025 update](https://blog.millerti.me/2023/01/22/encrypting-data-in-the-browser-using-webauthn/)
> on his original article:
>
> > **If you delete a passkey you will permanently lose access to all of its
> > PRF-protected data.** In such a scenario there is no way to recover
> > PRF-protected data. It's gone. Kaput!
> >
> > There are legitimate use cases for PRF. But before you go off and implement
> > some whiz-bang PRF-powered encryption system for your website, please keep
> > in mind that your users risk losing all of their encrypted data if they
> > ever delete (or even recreate) a passkey for your site. As the website
> > owner you will naturally bear the brunt of their ire — unless you
> > architected your use of PRF in a way that allows for "recovery" (of data,
> > of account access, etc.) in the case of passkey loss.
>
> Concretely: every passkey owns its own PRF input-key inside the authenticator.
> The relying party never sees that key, the user agent never sees that key,
> and there is no API to export it. Re-creating a passkey produces a brand-new
> input-key and a brand-new PRF output, even with the same salt — so the AES key
> derived from it is also brand-new and **cannot decrypt anything that was
> sealed under the previous passkey.**
>
> This demo is single-passkey, single-key by design — it does **not**
> implement recovery and exists purely to show the mechanism. A production
> design needs at least one of: a second passkey enrolled and salt-shared
> upfront, a server-side recovery wrap (KMS, …) escrowed behind a strong
> second factor, or an explicit "you will lose this data if you lose this
> passkey" UX contract the user accepts.

The relying party server hands the browser a per-credential salt at every
ceremony. The authenticator evaluates its credential-bound pseudo-random
function over that salt and the user agent surfaces the result as
`clientExtensionResults.prf.results.first`. The demo derives an AES-GCM key
from that PRF output via HKDF and uses it to **encrypt and decrypt arbitrary
items entirely inside the browser**. The server only ever sees the ciphertexts
and the salt — never the key, never the plaintext.

## Three pages, three phases

| Page | What it does |
|---|---|
| [`/register.html`](same-origin/public/register.html) | Registers a credential with the `prf` extension primed. Two salts are generated server-side, persisted next to the credential, and re-issued on every authentication. No items yet. |
| [`/vault.html`](same-origin/public/vault.html) | Authenticates with that credential to derive **two** keys (AES-GCM from `prf.results.first`, HMAC-SHA256 from `prf.results.second`), kept in tab memory only. Lets the user add items (label + plaintext, encrypted client-side + label/iv/ciphertext HMAC computed locally, all sent to the server) and decrypt items (server hands back the ciphertexts; the page decrypts and verifies the HMAC on demand). Reload → keys gone, re-authenticate. |
| [`/offline.html`](same-origin/public/offline.html) | Reuses the passkey registered through `/register.html`. That page mirrors `{credId, prfSalt, prfSalt2}` into `localStorage` automatically, so by the time you hit `/offline.html` everything is already there. Unlocks read from `localStorage`, run the PRF assertion against `rpId = location.hostname` with a locally-generated challenge, derive both keys, and load encrypted items from `localStorage`. A service worker caches the page on first load — disconnect / airplane mode and reload still works. |

## What it demonstrates

- **Registration** — the page calls
  `navigator.credentials.create({ publicKey: { …, extensions: { prf: { eval: { first: salt } } } } })`.
  The server validates with `AuthenticatorAttestationResponseValidator` and
  stores `(credential, salt)`.
- **Unlock** — the page calls
  `navigator.credentials.get({ publicKey: { …, extensions: { prf: { evalByCredential: { credId: { first: salt } } } } } })`
  with the salt the server re-issued. The browser returns the same PRF output
  → the same AES-GCM key. Server flips a per-session "vault unlocked" flag.
- **Encrypt-and-store** — every new item is AES-GCM-encrypted in the page
  using the in-memory key, then `POST /api/vault/items/add` with the
  `{label, ciphertext, iv}` triple. The server appends to the credential's
  item list without ever seeing the plaintext.
- **Decrypt-on-demand** — clicking *Decrypt* on an item runs Web Crypto's
  AES-GCM decrypt against the still-in-memory key. Clicking *Lock vault*
  drops the key and forces a re-authentication.

```
┌──────────────────┐     POST /api/register/options       ┌──────────────────────┐
│  register.html   │ ───────────────────────────────────▶ │  router.php (RP)     │
│  (browser)       │ ◀────────── creation options ─────── │  - lib + serializer  │
│                  │            extensions.prf.eval.first │  - PRF salt random   │
│                  │     POST /api/register/verify        │  - CredentialStore   │
│                  │ ───────────────────────────────────▶ │  Validator->check    │
└──────────────────┘                                      └──────────────────────┘

┌──────────────────┐     POST /api/vault/options          ┌──────────────────────┐
│  vault.html      │ ───────────────────────────────────▶ │  evalByCredential[id]│
│  (unlock phase)  │ ◀── options + stored items list ──── │      = stored salt   │
│                  │     POST /api/vault/verify           │  → vault_unlocked    │
│                  │ ───────────────────────────────────▶ │      session flag    │
└──────────────────┘                                      └──────────────────────┘
        │
        ├── PRF output → HKDF → AES-GCM key (kept in JS memory only)
        ▼
┌──────────────────┐     POST /api/vault/items/add        ┌──────────────────────┐
│  vault.html      │ ───────────────────────────────────▶ │  appendItem(...)     │
│  (use phase)     │       { label, ciphertext, iv }      │                      │
│  - encrypt       │     POST /api/vault/items/delete     │                      │
│  - decrypt       │ ───────────────────────────────────▶ │  deleteItem(itemId)  │
│  - delete        │                                      │                      │
└──────────────────┘                                      └──────────────────────┘
```

## Run it

```bash
cd docs/examples/prf-demo
./same-origin/run.sh
```

The script `composer install`s on first run and boots the demo on
<http://localhost:8000>. The shipped `composer.json` symlinks
`web-auth/webauthn-framework` from this checkout (`../../..`), so you get the
not-yet-released PRF builder code straight from `src/`. To run against a
published `^5.4` release once one exists, swap the path-repo block for the
standard packagist `web-auth/webauthn-lib` requirement.

Open <http://localhost:8000> in a browser that supports the PRF extension:

- A platform authenticator (Touch ID, Windows Hello, Android device unlock) or
  a hardware key that supports the `prf` extension. The specification is
  abstract over how the authenticator implements it, so PRF availability is not
  the same question as CTAP `hmac-secret` support: the client reports the answer
  through `prf.enabled` and the presence of `prf.results`.
- A secure context. `localhost` qualifies; otherwise serve over HTTPS.
- Chrome 116+ / Edge 116+ on the desktop side, recent Safari (iOS 18+ /
  macOS 15+). Firefox is still trailing as of this writing.

Walk through the pages in order:

1. <http://localhost:8000/register.html> — register a credential (online).
2. <http://localhost:8000/vault.html> — authenticate, then encrypt/decrypt (online).
3. <http://localhost:8000/offline.html> — uses the credential id + salts that step 1 mirrored to `localStorage`; the unlock ceremony and the encrypt/decrypt loop are 100% client-side. Once the page has loaded once, it survives airplane mode (service worker).

State (registered credentials, ciphertexts, in-flight challenges, the
"unlocked" flag) lives in a JSON file at `var/credentials.json` and the
PHP session.

## Why the PHP code is short

Most of the demo is boilerplate identical to a regular WebAuthn ceremony — the
only PRF-specific lines are this builder call:

```php
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtensionBuilder;

$options->extensions = AuthenticationExtensions::create([
    PseudoRandomFunctionInputExtensionBuilder::create()
        ->withInputs($salt)              // registration: global eval
        ->build(),
]);

// or, during authentication, per-credential salts:
$prf = PseudoRandomFunctionInputExtensionBuilder::create();
foreach ($credentialIds as $id) {
    $prf->withCredentialInputs(
        \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($id),
        $saltFor[$id],
    );
}
$options->extensions = AuthenticationExtensions::create([$prf->build()]);
```

The framework does **not** validate `clientExtensionResults.prf.results`
server-side, and intentionally so: the PRF output is a secret that lives in the
browser only. The lib's job is to surface the right inputs in the options sent
to the browser; the rest is Web Crypto inside the page.

That is not just a design choice here, it is what the specification requires.
W3C WebAuthn Level 3 states that authenticator extension outputs MUST NOT
contain cleartext PRF outputs, because the authenticator data is signed and the
client therefore cannot strip anything from it before the credential is posted
to the relying party server. Two practical rules follow:

- read the results from `getClientExtensionResults().prf.results` and nowhere
  else, and never post them to your own backend;
- a readable `prf` entry sitting in the authenticator extension outputs is a
  red flag, not usable key material. The library ships an opt-in
  `Webauthn\AuthenticationExtensions\PseudoRandomFunctionOutputChecker` that
  rejects such a response. It is not registered by default, since turning a
  previously accepted ceremony into a hard failure does not belong in a minor
  release. Add it to your `ExtensionOutputCheckerHandler` (or simply declare it
  as a service in a Symfony application) if you want the requirement
  enforced.

## Two PRF salts per ceremony

The W3C `prf` extension lets the relying party send **two** salts per
ceremony — `first` and `second`. The authenticator runs the PRF over both in a
single round-trip, the page receives both outputs in
`clientExtensionResults.prf.results.{first,second}`. The library exposes this
via the second argument of the builder methods:

```php
PseudoRandomFunctionInputExtensionBuilder::create()
    ->withInputs($salt, $salt2)                        // creation: both `eval` salts
    ->withCredentialInputs($credId, $salt, $salt2)     // assertion: both per-credential salts
    ->build();
```

This demo wires both salts end-to-end — server-side they live in
`CredentialStore`, client-side both outputs are logged on every ceremony — and
**uses only `first`** to derive the AES-GCM key. `second` is left unused so
the example stays readable, but typical use cases for it are:

- a separate HMAC key over the item labels, so the server cannot silently
  rename items;
- an envelope-key / data-key split (one for AES, one for key-wrapping);
- key rotation: at the rotation moment, run an assertion with `first = old
  salt` and `second = new salt`, decrypt under `first`, re-encrypt under
  `second`, then drop the old salt.

## Going fully offline

The PRF computation happens **inside the authenticator**, there is zero network
involved in evaluating the credential-bound pseudo-random function, and
`navigator.credentials.get()` itself does not hit the network. So once a passkey
is enrolled and its salt is sitting on the device, **the unlock ceremony is
100 % offline**: no fetch, no server roundtrip is needed to derive the AES key.

The server endpoints in this demo (`/api/vault/options`, `/api/vault/verify`,
`/api/vault/items/*`) exist for two reasons that are **not cryptographic**:

1. transport — they are how this demo ships the salt and the stored
   ciphertexts to the page. In an offline build that role moves to
   `localStorage` / IndexedDB / the Cache API;
2. server-side policy — `/api/vault/verify` flips a `vault_unlocked` session
   flag that gates `/api/vault/items/{add,delete}`. In an offline build there
   is no server to gate, so the flag and the call disappear.

To flip the demo to offline-only you adjust:

| Concern | Online demo (this code) | Offline-capable build |
|---|---|---|
| Where the ciphertext + IV live | server JSON file (`var/credentials.json`) | IndexedDB / localStorage / Cache API on the device |
| Where the per-credential salt lives | server JSON file | localStorage on the device (the salt is not a secret — it is sent in clear in the options on every ceremony) |
| Page availability without network | needs `php -S` running | installable PWA + service worker caching the static assets |
| `allowCredentials` in the assertion options | enumerated by the server | leave empty — works because we registered with `residentKey: 'required'` (discoverable / passkey) |
| Challenge | random bytes from the server, replay-checked at `/verify` | random bytes from `crypto.getRandomValues(new Uint8Array(32))` — fine because we are not proving authentication to a server, only invoking the PRF; AES-GCM's tag detects any wrong-key attempt |
| `rpId` | the relying party domain | same constraint — the PWA must be served from that domain |
| Server-side `→check()` validation | required, that's the whole point of WebAuthn login | skipped — no server is verifying the assertion in the offline path |

A bare-bones offline call inside an installed PWA would look like:

```js
const credId    = b64u.decode(localStorage.getItem('credId'));
const salt      = b64u.decode(localStorage.getItem('prfSalt'));
const blob      = JSON.parse(localStorage.getItem('vault')); // {iv, ciphertext}

const credential = await navigator.credentials.get({
    publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: location.hostname,
        allowCredentials: [{ type: 'public-key', id: credId }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
    },
});

const prfBytes = credential.getClientExtensionResults().prf.results.first;
// …same HKDF + AES-GCM decrypt as in vault.html…
```

`offline.html` in this demo implements the post-registration half of the
loop — unlock + add + decrypt — using the credential and the salts that
`register.html` writes to `localStorage` after a successful server-validated
register. The companion service worker `sw.js` caches the page so it loads
in airplane mode after a first online visit. Registration itself stays
online because the server still validates the attestation and persists the
salts (which makes `vault.html` available alongside `offline.html`).

## What this demo deliberately leaves out

- A real database / user system (uses a JSON file).
- **Recovery.** See the warning at the top of this README. If the user deletes
  the passkey, the encrypted items become permanently unreadable. A production
  design needs an explicit recovery story before turning PRF into the only key.
- Salt rotation — the salts are fixed per credential to keep the demo readable.
- Multi-credential UI / cross-origin / multi-RP setups.
- A long-lived "unlock" cookie — the `vault_unlocked` session flag stays only
  for the lifetime of the PHP session and is rotated on the next
  `/api/vault/options` call.
