Webauthn Framework
==================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/web-auth/webauthn-framework/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/web-auth/webauthn-framework/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/web-auth/webauthn-framework/badge.svg?branch=master)](https://coveralls.io/github/web-auth/webauthn-framework?branch=master)

[![Build Status](https://travis-ci.org/web-auth/webauthn-framework.svg?branch=v1.1)](https://travis-ci.org/web-auth/webauthn-framework)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/b7efa68f-8962-41cf-a2e3-4444426bc95a/big.png)](https://insight.sensiolabs.com/projects/b7efa68f-8962-41cf-a2e3-4444426bc95a)

[![Latest Stable Version](https://poser.pugx.org/web-auth/webauthn-framework/v/stable.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![Total Downloads](https://poser.pugx.org/web-auth/webauthn-framework/downloads.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![Latest Unstable Version](https://poser.pugx.org/web-auth/webauthn-framework/v/unstable.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![License](https://poser.pugx.org/web-auth/webauthn-framework/license.png)](https://packagist.org/packages/web-auth/webauthn-framework)

Webauthn defines an API enabling the creation and use of strong, attested, scoped, public key-based credentials by web applications, for the purpose of strongly authenticating users.

This framework contains PHP libraries and Symfony bundle to allow developpers to integrate that authentication mechanism into their web applications.

# Supported features

- Attestation Types
  - [x] basic attestation
  - [x] self attestation
  - [x] private CA attestation
  - [ ] elliptic curve direct anonymous attestation (optional)
- Attestation Formats
  - [x] FIDO U2F attestation
  - [x] packed attestation
  - [x] TPM attestation
  - [x] Android key attestation (optional) 
  - [x] Android Safetynet attestation
- Communication Channel Requirements
  - [ ] TokenBinding support (optional)
- Extensions
  - [x] registration and authentication support without extension
  - [x] extension support
  - [x] appid extension support (optional)
- Cose Algorithms
  - [x] RS1, RS256, RS384, RS512
  - [x] PS256, PS384, PS512
  - [x] ES256, ES384, ES512
  - [x] EdDSA

# Documentation

## Webauthn Library

With this library, you can add multi-factor authentication like FIDO U2F does or add passwordless authentication support for your application using the new FIDO2 Webauthn specification.

There are two steps to perform:

* [Associate the device to your user (Public Key Credential Creation)](doc/webauthn/PublicKeyCredentialCreation.md)
* [Check authentication request (Public Key Credential Request)](doc/webauthn/PublicKeyCredentialRequest.md)

Install the library with Composer: `composer require web-authn/webauthn-lib`.

## Symfony Bundles

This framework provides two bundles:

* **Webauthn Bundle**: this bundle uses the webauthn library to register services and attestation format supports. [The documentation can be found here](doc/symfony/index.md)
* **Webauthn Security Bundle**: this bundle adds a new firewall based on webauthn. You will be able to authenticate your users with their username and FIDO2 compatbile devices. [The documentation can be found here](doc/symfony-security/index.md)

## Other libraries

### FIDO U2F

FIDO U2F is an old protocol, but widely adopted by a lot of web services.
It adds a very robust and easy to use second factor authentication method.

The details for this lirary and the process are explained [in this dedicated page](doc/u2f/FIDO.md).

### Cose Key

TO BE WRITTEN

# Support

I bring solutions to your problems and answer your questions.

If you really love that project and the work I have done or if you want I prioritize your issues, then you can help me out for a couple of :beers: or more!

[![Become a Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/FlorentMorselli)

# Contributing

Requests for new features, bug fixed and all other ideas to make this framework useful are welcome.
If you feel comfortable writing code, you could try to fix [opened issues where help is wanted](https://github.com/web-auth/webauthn-framework/issues?q=label%3A%22help+wanted%22) or [those that are easy to fix](https://github.com/web-auth/webauthn-framework/labels/easy-pick).

Do not forget to [follow these best practices](.github/CONTRIBUTING.md).

**If you think you have found a security issue, DO NOT open an issue**. [You MUST submit your issue here](https://gitter.im/Spomky/).

# Licence

This software is release under [MIT licence](LICENSE).
