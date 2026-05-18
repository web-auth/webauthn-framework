# Signal API Demo, `web-auth/webauthn-lib`

Pure-PHP example that exercises the three W3C
[Signal](https://w3c.github.io/webauthn/#sctn-signal-methods) methods
the spec exposes for keeping passkey-manager state in sync with the
relying party.

The Signal API runs **entirely in the browser**. The framework's job
is just to hand the page a fresh, authoritative snapshot of what the
RP currently considers valid: which credential IDs are still accepted
for a user, and what the up-to-date `name` / `displayName` should be.
The page then issues the JS calls.

## The three methods

| Call | When this demo fires it |
|---|---|
| `PublicKeyCredential.signalUnknownCredential({ rpId, credentialId })` | Right after `POST /api/account/passkey/delete` succeeds. Tells the passkey manager: this credential id is no longer recognised by the RP, prune it. |
| `PublicKeyCredential.signalAllAcceptedCredentials({ rpId, userId, allAcceptedCredentialIds })` | On page load, after enrolling a passkey, after deleting one. The full, authoritative list of accepted credential IDs for the user. The manager prunes anything not in the list. |
| `PublicKeyCredential.signalCurrentUserDetails({ rpId, userId, name, displayName })` | On page load, after the user renames the account. Refreshes the human-readable identity associated with this user in the manager UI. |

Each unsupported method falls back to a no-op + a log line, so the demo
keeps working on browsers that lack Signal support.

## Four pages

| Page | What it does |
|---|---|
| [`/`](same-origin/public/index.html) | Landing page, explains the API and shows the current session state. |
| [`/register.html`](same-origin/public/register.html) | Standard registration ceremony, copied from the basic-demo. |
| [`/login.html`](same-origin/public/login.html) | Standard assertion ceremony, copied from the basic-demo. |
| [`/account.html`](same-origin/public/account.html) | The Signal API playground. Shows feature-detection results for the three methods, lets the user edit the display name (auto-fires `signalCurrentUserDetails`), enrol/rename/delete passkeys (auto-fires the relevant signals), and trigger any signal manually with explicit buttons. The action log shows every call as it happens. |

## What the server contributes

A single new endpoint, `GET /api/account/signal-payload`, returns the
canonical snapshot:

```json
{
  "rpId": "localhost",
  "userId": "base64url-of-user-handle",
  "name": "jane.doe@example.com",
  "displayName": "Jane Doe",
  "allAcceptedCredentialIds": ["base64url-1", "base64url-2"]
}
```

The page reads this every time it is about to make a Signal call.
Everything else is the same as the basic-demo:
`register/options`+`verify`, `login/options`+`verify`,
`account/passkey/{add,rename,delete}`, plus a new `account/rename` for
changing the display name.

## Run it

```bash
cd docs/examples/signal-api-demo
./same-origin/run.sh
```

Walk through:

1. <http://localhost:8000/register.html>, register a passkey.
2. <http://localhost:8000/account.html>:
   - watch the support panel at the top, it tells you which Signal
     methods your browser exposes;
   - the page auto-fires `signalCurrentUserDetails` and
     `signalAllAcceptedCredentials` on load, you should see them in
     the activity log;
   - change the display name, hit *Save*: the server stores the
     change, then `signalCurrentUserDetails` is sent;
   - enrol a second passkey, the page fires
     `signalAllAcceptedCredentials` with the new id;
   - delete one, the page fires `signalUnknownCredential` with the
     deleted id, then `signalAllAcceptedCredentials` with the
     remaining ones.
3. Open your OS passkey manager (macOS Keychain, Windows Settings ->
   Sign-in options -> Passkeys, Android Google Password Manager) and
   verify the changes propagated.

## Browser support

Signal is recent. Chromium-based browsers (Chrome 132+, Edge 132+)
landed it first, Safari followed in 18.x. Firefox is trailing as of
this writing. The account page detects each method individually so
partial support is handled gracefully.

## What lives in `var/`

Same shape as the basic-demo:

- `var/users.json`: `username -> { userHandle, displayName, createdAt }`.
- `var/credentials.json`: `credentialId -> { userHandle, credentialId,
  source, label, addedAt, lastUsedAt }`.

Delete the two JSON files to reset the demo.

## Where to look in the code

| What | File |
|---|---|
| Service wiring | [`src/bootstrap.php`](src/bootstrap.php) |
| User table (also exposes `updateDisplayName`) | [`src/UserStore.php`](src/UserStore.php) |
| Credential persistence | [`src/CredentialStore.php`](src/CredentialStore.php) |
| HTTP endpoints including `/api/account/signal-payload` and `/api/account/rename` | [`same-origin/router.php`](same-origin/router.php) |
| Browser side, all three Signal calls + auto-fire wiring | [`same-origin/public/account.html`](same-origin/public/account.html) |
