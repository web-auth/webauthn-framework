CHANGELOG
=========

*For versions 1.x, only major and minor versions are listed.*
*Patch version details are available for other releases.* 

Version 2.0.0
-------------

This major version do not add any new feature.
It corresponds to the last version of the previous major branch **where deprecations have been removed**.

To migrate to that new major versions, you should make your code deprecation free first.
When done, you can use this new major branch.

Version 1.2
-----------

* New features:
    * New firewall dedicated to scripting applications (e.g. SPA)
* Deprecations:
    * Package `web-auth/webauthn-symfony-security-bundle`

Version 1.1
-----------

* New features:
    * Package `web-auth/conformance-toolset`
    * Class `Webauthn\PublicKeyCredentialSourceRepository`
    * Android Safety-Net Attestation Statement Support
    * Extension Output Checker Handler
    * Cose Signature Algorithms
* Deprecations:
    * Property `PublicKeyCredentialParameters::ALGORITHM_ES256`
    * Property `PublicKeyCredentialParameters::ALGORITHM_RS256`
    * Class `Webauthn\CredentialRepository`

Version 1.0
-----------

Initial release.
