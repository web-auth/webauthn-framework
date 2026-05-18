# Passkey Upgrade Demo, `web-auth/webauthn-lib`

Pure-PHP example of the **passkey upgrade** flow, the most common
real-world rollout pattern:

1. Accounts are born with a username and a password (classic signup).
2. Once signed in, the account page offers to enrol a passkey for
   faster sign-in next time.
3. Future logins accept either factor on the same form, so the user can
   migrate at their own pace.

The password is always a usable fallback, so losing every passkey is
not the dead-end it is in the [basic-demo](../basic-demo).

## Four pages, three flows

| Page | What it does |
|---|---|
| [`/`](same-origin/public/index.html) | Landing page, shows the current session state, including which factor opened it (`authMethod`). |
| [`/signup.html`](same-origin/public/signup.html) | Creates a brand-new account with `username + password + displayName`. The password is hashed with `password_hash(PASSWORD_BCRYPT)` and the session opens with `authMethod = 'password'`. |
| [`/login.html`](same-origin/public/login.html) | Sign-in page that accepts both factors. The submit button uses the password, an "Use a passkey instead" button switches to a WebAuthn assertion. The page falls back gracefully when the account has no passkey enrolled. |
| [`/account.html`](same-origin/public/account.html) | Protected page. Shows the active `authMethod`, lists enrolled passkeys (label, AAGUID, counter, backup state, last used), surfaces a yellow upgrade CTA when no passkey is enrolled, and lets the user enrol, rename or delete passkeys. Deleting the last passkey is allowed because the password fallback is still there. |

## What this demo demonstrates

- A password-only signup endpoint and a `password_verify`-driven login.
- A login form that supports both factors so users can migrate at their
  own pace.
- The **passkey upgrade** call from `/account.html`:
  `POST /api/account/passkey/add/options` then verify, with
  `excludeCredentials` pre-filled to avoid double-enrolment of the same
  authenticator.
- An `authMethod` session field that tells the account page how the
  user got in. A production RP would use that to decide whether to
  require a step-up re-auth (re-type the password, recent strong
  factor, ...) before the passkey enrolment.

## Security note about the upgrade step

The demo enrols a passkey on any logged-in session, including one
opened by a password sign-in moments ago. A production RP **MUST** ask
for a re-auth right before the enrolment, otherwise a stolen password
lets an attacker silently bind their own passkey to the victim's
account. Common patterns are:

- re-type the password on the enrol page;
- send a one-time code by email and require it;
- require that the current session opened with a strong factor within
  the last `N` minutes.

The same applies to passkey delete in a production setting.

## Run it

```bash
cd docs/examples/passkey-upgrade-demo
./same-origin/run.sh
```

Then walk through the pages in order:

1. <http://localhost:8000/signup.html>, create an account.
2. <http://localhost:8000/account.html>, click *Enrol a passkey* in the
   upgrade CTA.
3. *Sign out* and head to <http://localhost:8000/login.html>. Try both
   sign-in paths: the password submit button, and the *Use a passkey
   instead* button.

## What lives in `var/`

- `var/users.json`: `username -> { userHandle, displayName,
  passwordHash, createdAt }`. The password is bcrypt-hashed; the user
  handle is a random 32-byte blob generated at signup.
- `var/credentials.json`: same shape as the basic-demo,
  `credentialId -> { userHandle, credentialId, source, label, addedAt,
  lastUsedAt }`.

Delete the two JSON files to reset the demo.

## What this demo deliberately leaves out

- Email verification, password reset, account recovery.
- Step-up re-auth before passkey enrolment (see the security note
  above).
- Rate limiting, CSRF, password policy beyond minimum length.

## Where to look in the code

| What | File |
|---|---|
| Service wiring | [`src/bootstrap.php`](src/bootstrap.php) |
| User table with password hash and user handle | [`src/UserStore.php`](src/UserStore.php) |
| Credential persistence | [`src/CredentialStore.php`](src/CredentialStore.php) |
| All HTTP endpoints (signup, password login, passkey login, passkey enrol, ...) | [`same-origin/router.php`](same-origin/router.php) |
| Browser side, password signup | [`same-origin/public/signup.html`](same-origin/public/signup.html) |
| Browser side, dual-factor login | [`same-origin/public/login.html`](same-origin/public/login.html) |
| Browser side, account + upgrade CTA | [`same-origin/public/account.html`](same-origin/public/account.html) |
