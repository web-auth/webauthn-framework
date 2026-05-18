# Basic Demo, `web-auth/webauthn-lib`

A minimal end-to-end pure-PHP example of a username-based passkey login,
using only `web-auth/webauthn-lib` (no Symfony bundle, no Doctrine). The
demo runs on the PHP built-in web server and persists everything to JSON
files under `var/`. It exists to answer the most common question raised on
[issue #649](https://github.com/web-auth/webauthn-framework/issues/649):

> What do I actually have to wire up, and what do I have to store?

## Four pages, three flows

| Page | What it does |
|---|---|
| [`/`](same-origin/public/index.html) | Landing page, shows whether you are signed in and links to the other pages. |
| [`/register.html`](same-origin/public/register.html) | Creates a brand-new account secured by a passkey. The page calls `navigator.credentials.create()`, the server validates the attestation with `AuthenticatorAttestationResponseValidator` and persists a `CredentialRecord` bound to the user handle. |
| [`/login.html`](same-origin/public/login.html) | Authenticates an existing account. The page calls `navigator.credentials.get()` with a server-issued `allowCredentials` list, the server validates the assertion with `AuthenticatorAssertionResponseValidator`, updates the counter and opens a PHP session. |
| [`/account.html`](same-origin/public/account.html) | Protected page. Lists registered passkeys (label, AAGUID, counter, backup state, last used), lets you add another passkey on the current account (`excludeCredentials` pre-filled), rename a passkey or delete one. The last passkey of an account cannot be deleted. |

## What this demo demonstrates

- **The four endpoints** every relying party needs:
  `POST /api/register/options`, `POST /api/register/verify`,
  `POST /api/login/options`, `POST /api/login/verify`.
- **What to store** after a successful registration: the framework's
  `CredentialRecord` serialized to JSON, plus the user handle binding and
  any application metadata (label, timestamps). See
  [`src/CredentialStore.php`](src/CredentialStore.php) for the canonical
  shape.
- **What to update** after a successful assertion: the same
  `CredentialRecord`, because the validator mutates the counter and the
  backup flags in place. Persisting the updated record is what makes the
  W3C clone-detection rule work over time.
- **How to enrol additional passkeys** on an existing account, with
  `excludeCredentials` pre-filled so the user agent refuses to register
  the same authenticator twice.
- **The "last passkey" rule**: a relying party without an account-recovery
  fallback (password, magic link, ...) MUST refuse to delete the last
  passkey of an account, otherwise losing it locks the user out for good.

```
+------------------+     POST /api/register/options       +----------------------+
|  register.html   | ----------------------------------->  |  router.php (RP)     |
|  (browser)       | <---------- creation options -------  |  - serializer       |
|                  |                                       |  - validators        |
|                  |     POST /api/register/verify         |  - UserStore         |
|                  | ----------------------------------->  |  - CredentialStore   |
+------------------+                                       +----------------------+

+------------------+     POST /api/login/options          +----------------------+
|  login.html      | ----------------------------------->  |  allowCredentials    |
|  (browser)       | <-------- request options ---------   |  pre-filled per user |
|                  |     POST /api/login/verify            |                      |
|                  | ----------------------------------->  |  updates counter +   |
|                  |                                       |  opens PHP session   |
+------------------+                                       +----------------------+
```

## Run it

```bash
cd docs/examples/basic-demo
./same-origin/run.sh
```

The script `composer install`s on first run and boots the demo on
<http://localhost:8000>. The shipped `composer.json` symlinks
`web-auth/webauthn-framework` from this checkout (`../../..`). To run
against a published `^5.4` release once one exists, swap the path-repo
block for the standard packagist `web-auth/webauthn-lib` requirement.

Open <http://localhost:8000> in a browser with passkey support:

- A platform authenticator (Touch ID, Windows Hello, Android device
  unlock) or a roaming hardware key.
- A secure context. `localhost` qualifies; otherwise serve over HTTPS.

Walk through the pages in order:

1. <http://localhost:8000/register.html>, register a passkey on a fresh
   account, you are redirected to `/account.html` automatically.
2. (Optional) hit *Sign out* on `/account.html`, then
   <http://localhost:8000/login.html> to authenticate again with the same
   passkey.
3. <http://localhost:8000/account.html>, click *Add another passkey* to
   enrol a second device on the same account, then try renaming and
   deleting passkeys.

## What lives in `var/`

State is persisted to two JSON files so the demo survives across HTTP
requests with `php -S`:

- `var/users.json`: `username -> { userHandle, displayName, createdAt }`.
- `var/credentials.json`: `credentialId -> { userHandle, credentialId,
  source, label, addedAt, lastUsedAt }`. The `source` field holds the
  whole `CredentialRecord` JSON, which is the only blob the framework
  needs to verify the next assertion.

Delete the two JSON files to reset the demo.

## What this demo deliberately leaves out

- A real database. Production code MUST plug
  `Webauthn\CredentialRecordRepositoryInterface` and (optionally)
  `Webauthn\CanSaveCredentialRecord` against a real persistence layer.
  The Symfony bundle ships a Doctrine implementation
  (`DoctrineCredentialSourceRepository`) that doubles as a reference.
- **Account recovery.** Lose every registered passkey and the account is
  unreachable. A production design needs a fallback: a second passkey
  enrolled upfront, a password backup, an email magic link, ...
- Email verification, password backup, CSRF protection, rate limiting,
  attestation chain verification (the demo accepts the `none` format
  only).
- Multi-RP / cross-origin setups; see the `spc-demo` for cross-origin
  patterns.

## Where to look in the code

| What | File |
|---|---|
| Service wiring (serializer, validators, allowed origins) | [`src/bootstrap.php`](src/bootstrap.php) |
| User table (username -> userHandle mapping) | [`src/UserStore.php`](src/UserStore.php) |
| Credential persistence (the part that answers "what do I store?") | [`src/CredentialStore.php`](src/CredentialStore.php) |
| All HTTP endpoints | [`same-origin/router.php`](same-origin/router.php) |
| Browser side, attestation | [`same-origin/public/register.html`](same-origin/public/register.html) |
| Browser side, assertion | [`same-origin/public/login.html`](same-origin/public/login.html) |
| Browser side, account management | [`same-origin/public/account.html`](same-origin/public/account.html) |
