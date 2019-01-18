FIDO2/Webauthn Bundle for Symfony
=================================

**FIDO2/Webauthn Bundle for Symfony** is a **Symfony Bundle** that will help you to manage attestation or assertion requests and responses computed by security devices.

# Installation

Install the library with Composer: `composer require web-auth/webauthn-symfony-bundle`.

# Contribution

This repository is a sub repository of [the Web Authentication Framework](https://github.com/web-auth/webauthn-framework) project and is **READ ONLY**.

**Please do not submit any Pull Request here.**
You should go to [the main repository](https://github.com/web-auth/webauthn-framework) instead.

# Documentation

The official documentation is available at https://github.com/web-auth/webauthn-framework 

# Missing Features

* Attestation Statement Formats:
    * [Android SafetyNet Attestation Statement Format](https://www.w3.org/TR/webauthn/#android-safetynet-attestation)
    * [Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn/#android-key-attestation)
    * [TPM Attestation Statement Format](https://www.w3.org/TR/webauthn/#tpm-attestation)
    * [ECDAA and SelfAttestation for Packed Attestation Format](https://www.w3.org/TR/webauthn/#packed-attestation)
* Token Binding support (see [#2](https://github.com/web-auth/webauthn-framework/issues/2))
* [Extension support](https://www.w3.org/TR/webauthn/#extensions) is implemented but not fully tested

# Support

I bring solutions to your problems and answer your questions.

If you really love that project and the work I have done or if you want I prioritize your issues, then you can help me out for a couple of :beers: or more!

[![Become a Patreon](https://c5.patreon.com/external/logo/become_a_patron_button.png)](https://www.patreon.com/FlorentMorselli)

# Licence

This project is release under [MIT licence](LICENSE).
