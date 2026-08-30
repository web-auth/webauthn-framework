# Usernameless (discoverable) Demo, `web-auth/webauthn-lib`

A pure-PHP example of a sign-in flow that does NOT take a username as
input. Companion to the [basic-demo](../basic-demo). The relying party
hands the browser an assertion challenge with an empty
`allowCredentials` list and the user agent surfaces a Conditional UI
passkey picker. Server-side, the account is resolved from the credential
id plus the user handle the authenticator returns in
`response.userHandle`.

## Four pages, three flows

| Page | What it does |
|---|---|
| [`/`](same-origin/public/index.html) | Landing page, shows the current session state and links to the other pages. |
| [`/register.html`](same-origin/public/register.html) | Creates an account secured by a discoverable passkey. The page calls `navigator.credentials.create()` with `residentKey: required` and `userVerification: required`. The authenticator stores the user handle locally so future sign-ins can surface this account without being told a username. |
| [`/login.html`](same-origin/public/login.html) | Signs the user in without a username. The page calls `navigator.credentials.get({ mediation: 'conditional', publicKey })` on load to arm a Conditional UI picker; a manual fallback button is also provided. The server identifies the user from the credential id and verifies that `response.userHandle` matches the binding stored at registration. |
| [`/account.html`](same-origin/public/account.html) | Same passkey management UI as the basic-demo: list, add another passkey (also discoverable), rename, delete. The last passkey of an account cannot be deleted. |

## How it differs from the basic-demo

| Concern | basic-demo | usernameless-demo |
|---|---|---|
| `residentKey` at registration | `preferred` (works either way) | `required` (forces a discoverable credential) |
| `userVerification` at registration | `preferred` | `required` (so the credential is a single-factor passkey) |
| Login form | username input | no input; Conditional UI picker via `autocomplete="username webauthn"` + a manual fallback button |
| `allowCredentials` at sign-in | populated from the user's stored credentials | empty (`[]`); the authenticator picks any matching credential |
| Server-side user lookup at verify | by session-stored username | by credential id, then verified against `response.userHandle` |

## Run it

```bash
cd docs/examples/usernameless-demo
./same-origin/run.sh
```

The script `composer install`s on first run and boots the demo on
<http://localhost:8000>. The shipped `composer.json` symlinks
`web-auth/webauthn-framework` from this checkout (`../../..`).

Open <http://localhost:8000> in a browser with passkey support AND
Conditional UI support:

- Chrome 108+, Edge 108+, Safari 16+, Firefox 119+ for Conditional UI.
- A platform authenticator (Touch ID, Windows Hello, Android device
  unlock) or a roaming hardware key.
- A secure context (`localhost` qualifies).

Walk through the pages in order:

1. <http://localhost:8000/register.html>, register a discoverable
   passkey. You are redirected to `/account.html`.
2. Hit *Sign out* on `/account.html`, then
   <http://localhost:8000/login.html>. Click the username field, the
   browser should offer the passkey you just registered. Pick it.
3. On <http://localhost:8000/account.html> click *Add another passkey* to
   enrol a second device (also as a discoverable credential).

## What lives in `var/`

Same shape as the basic-demo:

- `var/users.json`: `username -> { userHandle, displayName, createdAt }`.
- `var/credentials.json`: `credentialId -> { userHandle, credentialId,
  source, label, addedAt, lastUsedAt }`. The `source` field holds the
  `CredentialRecord` JSON.

Delete the two JSON files to reset the demo.

## What this demo deliberately leaves out

- A real database. Production code MUST plug a real
  `Webauthn\CredentialRecordRepositoryInterface` against a real
  persistence layer.
- Account recovery, email verification, CSRF, rate limiting, ...
- Multi-RP / cross-origin setups.

## Where to look in the code

| What | File |
|---|---|
| Service wiring | [`src/bootstrap.php`](src/bootstrap.php) |
| User table (username -> userHandle mapping) | [`src/UserStore.php`](src/UserStore.php) |
| Credential persistence | [`src/CredentialStore.php`](src/CredentialStore.php) |
| All HTTP endpoints, including the usernameless login | [`same-origin/router.php`](same-origin/router.php) |
| Browser side, attestation with `residentKey: required` | [`same-origin/public/register.html`](same-origin/public/register.html) |
| Browser side, assertion with Conditional UI | [`same-origin/public/login.html`](same-origin/public/login.html) |
| Browser side, account management | [`same-origin/public/account.html`](same-origin/public/account.html) |
