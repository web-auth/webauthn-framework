# CHANGELOG

_Only major and minor versions are listed._

## Version 2.0

This major version do not add any new feature.
It corresponds to the last version of the previous major branch **where deprecations have been removed**.

Additionally, the following changes have to be taken into account:

1. The AAGUID

The AAGUID of the `Webauthn\AttestedCredentialData` or `Webauthn\PublicKeyCredentialSource` object in the constructor
or returned by the method `getAaguid()` are now an instance of a `Ramsey\Uuid\UuidInterface` object.

To migrate to that new major versions, you should make your code deprecation free first.
When done, you can use this new major branch.

## Version 1.2

-   New features:
    -   New firewall dedicated to scripting applications (e.g. SPA)
-   Deprecations:
    -   Package `web-auth/webauthn-symfony-security-bundle`

## Version 1.1

-   New features:
    -   Package `web-auth/conformance-toolset`
    -   Class `Webauthn\PublicKeyCredentialSourceRepository`
    -   Android Safety-Net Attestation Statement Support
    -   Extension Output Checker Handler
    -   Cose Signature Algorithms
-   Deprecations:
    -   Property `PublicKeyCredentialParameters::ALGORITHM_ES256`
    -   Property `PublicKeyCredentialParameters::ALGORITHM_RS256`
    -   Class `Webauthn\CredentialRepository`

## Version 1.0

Initial release.
