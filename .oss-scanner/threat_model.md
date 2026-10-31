# Threat model

This file steers the [OSS Scanner](https://github.com/anthropics/oss-scanner). Vulnerabilities found by other means
are reported as described in [SECURITY.md](../SECURITY.md).

## What this project does

A monorepo of three packages, each mirrored to a read-only repository:

- `src/webauthn` (`web-auth/webauthn-lib`): the server side of the W3C Web Authentication specification, Level 3.
  It builds the options sent to the browser and verifies the registration (attestation) and authentication
  (assertion) responses the browser sends back. It has no framework dependency.
- `src/symfony` (`web-auth/webauthn-symfony-bundle`): the Symfony integration. JSON endpoints for both ceremonies,
  security authenticators for the firewall, storage of the options between the two steps of a ceremony, Doctrine
  types for the credential records.
- `src/stimulus` (`web-auth/webauthn-stimulus`): Stimulus controllers that run the ceremonies in the browser with
  `@simplewebauthn/browser` and post the results to the bundle endpoints.

The relying party (RP) is the application that uses the framework. Its users sign in with passkeys or security keys.

## Where untrusted input enters

The attacker is anyone who can send HTTP requests to the RP, including a user who controls their own browser or
authenticator and crafts what they return. Everything the browser sends is untrusted:

- The options requests (`/login/options` and `/register/options` on the firewall by default, or the paths of the
  `controllers` section): the username, the display name, and the fields the client may override. Which fields can
  be overridden, and with which values, is decided by `ClientOverridePolicy` (`src/symfony/src/Policy`) or by the
  deprecated `client_override_policy` section of the configuration.
- The `PublicKeyCredential` JSON posted to the result endpoints: `clientDataJSON`, `attestationObject`,
  `authenticatorData`, `signature`, `userHandle`, `rawId`, `transports` and `clientExtensionResults`. It is
  deserialized by `src/webauthn/src/Denormalizer`, then parsed as JSON (client data), as CBOR (attestation object,
  extensions, COSE keys) and as a binary layout (`AuthenticatorDataLoader`, `StringStream`).
- The attestation statements and their certificates: `packed`, `fido-u2f`, `tpm`, `android-key`, `apple`, `compound`
  and `none` (`src/webauthn/src/AttestationStatement`). TPM structures, ASN.1 extensions and X.509 chains are
  controlled by the attacker until they chain to a trust anchor.
- The Secure Payment Confirmation client data and its browser-bound signature
  (`src/webauthn/src/SecurePaymentConfirmation`).

What is trusted:

- The configuration of the bundle and of the library: RP ID, allowed origins, algorithms, profiles, override policy,
  firewall. An insecure default is a vulnerability. An insecure value that the RP has to set explicitly, and that the
  documentation flags, is not.
- The options kept on the server side between the two steps of a ceremony (`src/symfony/src/Security/Storage`). They
  are looked up by the challenge and can be used once. The client never supplies the options its response is
  verified against.
- The credential records and user entities returned by the repositories of the RP.
- The metadata statements and status reports loaded from the sources the RP configures
  (`src/webauthn/src/MetadataService`). How they are loaded and verified is in scope.

## Security properties that must hold

- A user signs in only with a credential registered to their account, with a valid signature over the authenticator
  data and the hash of the client data, for the challenge issued for that ceremony.
- No one can register a credential on another user's account, and a response cannot be replayed or used for another
  ceremony.
- The origin of the client data is one of the allowed origins (scheme, host and port, or an exact non-URL origin
  such as an Android application), or one of their subdomains when `allow_subdomains` is set. With no allowed origin
  configured, it is an HTTPS origin whose host is the RP ID, or one of its subdomains when `allow_subdomains` is set.
  The top origin of a cross-origin ceremony is checked by the configured top origin validator.
- The RP ID hash matches, and the user presence and user verification flags are enforced as the server requested.
- When attestation is verified, a certificate chain that does not lead to a trust anchor, or an authenticator that
  the status reports flag, is rejected.
- The signature counter and the backup flags are consistent with the stored record.
- When the fake credential generator is enabled, unknown usernames cannot be told apart from known ones.
- No secret, credential material or personal data is written to the logs.

## Components that matter most

- The ceremony steps (`src/webauthn/src/CeremonyStep`, assembled by `CeremonyStepManagerFactory`) and the two
  validators, `AuthenticatorAttestationResponseValidator` and `AuthenticatorAssertionResponseValidator`.
- The parsers of untrusted input: `AuthenticatorDataLoader`, `AttestationObjectLoader`, `StringStream`,
  `CollectedClientData`, the denormalizers and the attestation statement supports, TPM and Android Key first.
- The certificate chain validator (`src/webauthn/src/MetadataService/CertificateChain`). It downloads the CRLs named
  by the certificates of a chain that validated against a trust anchor; making the server request a URL taken from a
  certificate that did not is in scope.
- The Symfony security integration (`src/symfony/src/Security`): both authenticators (`Authentication` and
  `Http/Authenticator`), the options storage, the user entity guessers and the success and failure handlers.
- The controllers (`src/symfony/src/Controller`), including the `.well-known` endpoints for related origins and
  passkey endpoints.

Less important but in scope: the Doctrine types, the profiler data collector, the Signal API helpers and the Stimulus
controllers (`src/stimulus/assets/src`). Deprecated code paths are in scope as long as they ship.

## How to exercise it

The image has PHP 8.4, the dependencies installed in `vendor/` and `node_modules/`, and the QA tools of the CI image
on the `PATH`. Run the PHP tests as the CI does, with `phpunit-11`; `vendor/bin/phpunit` is another major version and
does not match the CI:

    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist
    composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --filter SecuredAreaTest
    npm test

- `tests/library/Functional` replays responses recorded from real authenticators through the validators. A
  reproducer for the library goes there or in `tests/library/Unit`.
- `tests/symfony/functional` boots a Symfony kernel (`AppKernel`, configuration in `tests/symfony/config`) and
  drives the firewall and the controllers over HTTP with the test client; `Firewall/SecuredAreaTest.php` and
  `Firewall/RegistrationAreaTest.php` show both ceremonies end to end. A reproducer for the bundle goes there.
- `tests/library/certificates` and `tests/metadataStatements` hold certificates and metadata statements.

## How we rate severity

- Critical: taking over an account without the victim's authenticator, in the default configuration. For example
  signing in as another user, registering a credential on another user's account, skipping the signature, challenge
  or RP ID hash check, or executing code or reading files through the processing of a response.
- High: the same in a documented, non-default configuration; a check that the configuration turns on and that does
  not run or can be skipped (attestation trust path, status reports, required user verification); an origin check
  bypass that does not need the attacker to control anything on an allowed host; a server-side request to a URL
  chosen by the attacker.
- Medium: an origin check bypass that needs control of another scheme, port or subdomain of an allowed host; direct
  username enumeration; secrets, credential material or personal data in the logs; a single unauthenticated request
  that costs the server disproportionately (deeply nested CBOR, oversized certificate chains, unbounded loops).
- Low: a defense in depth weakened under a documented misconfiguration (fake credentials, counter); a user
  verification downgrade that still needs physical possession of the victim's authenticator; disclosure of
  non-sensitive internals; a denial of service that needs sustained traffic.

For calibration, the published advisories were rated as follows:

- GHSA-875x-g8p7-5w27, enumeration of valid usernames: medium.
- GHSA-f7pm-6hr8-7ggm, `allowed_origins` collapsing URL-like origins to host-only values: medium.
- GHSA-q683-8468-r6h6, sensitive HTTP headers in INFO-level logs: medium.
- GHSA-h4fw-6r7f-w494, user verification downgrade through a default-open `ClientOverridePolicy`: low.
- GHSA-gq4g-fpc9-vjfq, predictable fake credentials with an empty secret: low.

## Anything to leave alone

- Bugs in the dependencies (`spomky-labs/cbor-php`, `web-auth/cose-lib`, `spomky-labs/pki-framework`,
  `web-token/jwt-library`, Symfony, Doctrine): they are separate projects.
- `tests/`, `bin/`, `.ci-tools/`, and the `Dummy*` classes of the bundle, which only throw until the application
  configures its own services.
- Hardening that the specification leaves to the RP (rate limiting, account recovery, session management after
  sign-in), unless the framework claims to provide it.
- Insecure values that the RP sets explicitly and that the documentation flags, such as HTTP origins for local
  development.

## Reports

Include a reproducer written as a PHPUnit test in one of the directories above, the configuration it needs when it is
not the default one, and a patch against the scanned branch. The maintainers port the fix to the maintained branches.
