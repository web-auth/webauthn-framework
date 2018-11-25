Webauthn Framework
==================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/web-auth/webauthn-framework/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/web-auth/webauthn-framework/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/web-auth/webauthn-framework/badge.svg?branch=master)](https://coveralls.io/github/web-auth/webauthn-framework?branch=master)

[![Build Status](https://travis-ci.org/web-auth/webauthn-framework.svg?branch=master)](https://travis-ci.org/web-auth/webauthn-framework)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/b7efa68f-8962-41cf-a2e3-4444426bc95a/big.png)](https://insight.sensiolabs.com/projects/b7efa68f-8962-41cf-a2e3-4444426bc95a)

[![Latest Stable Version](https://poser.pugx.org/web-auth/webauthn-framework/v/stable.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![Total Downloads](https://poser.pugx.org/web-auth/webauthn-framework/downloads.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![Latest Unstable Version](https://poser.pugx.org/web-auth/webauthn-framework/v/unstable.png)](https://packagist.org/packages/web-auth/webauthn-framework)
[![License](https://poser.pugx.org/web-auth/webauthn-framework/license.png)](https://packagist.org/packages/web-auth/webauthn-framework)

# Documentation

## FIDO U2F Library

FIDO U2F is an old protocol, but widely adopted by a lot of web services.
It adds a very robust and easy to use second factor authentication method.

The details for this lirary and the process are explained [in this dedicated page](doc/u2f/FIDO.md).

## Webauthn Library

With this library, you can add multi-factor authentication like FIDO U2F does or add passwordless authentication support for your application using the new FIDO2 Webauthn specification.

There are two steps to perform:

* [Associate the device to your user (Public Key Credential Creation)](doc/webauthn/PublicKeyCredentialCreation.md)
* [Check authentication request (Public Key Credential Request)](doc/webauthn/PublicKeyCredentialRequest.md)

## Symfony Bundle

*To be written*

# Support

I bring solutions to your problems and answer your questions.

If you really love that project and the work I have done or if you want I prioritize your issues, then you can help me out for a couple of :beers: or more!

[![Become a Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/FlorentMorselli)

# Contributing

Requests for new features, bug fixed and all other ideas to make this framework useful are welcome.
If you feel comfortable writing code, you could try to fix [opened issues where help is wanted](https://github.com/web-auth/webauthn-framework/labels/help+wanted) or [those that are easy to fix](https://github.com/web-auth/webauthn-framework/labels/easy-pick).

Do not forget to [follow these best practices](.github/CONTRIBUTING.md).

**If you think you have found a security issue, DO NOT open an issue**. [You MUST submit your issue here](https://gitter.im/Spomky/).

# Licence

This software is release under [MIT licence](LICENSE).
