Symfony UX Webauthn
================

Symfony UX Webauthn is a Symfony bundle integrating `Webauthn`_ in
Symfony applications. It is *not* part of `the Symfony UX initiative`_.

Webauthn is a complete and easy to use way to interact with Webauthn servers.
Just pass the form data, and it will interact with FIDO/FIDO2 Authenticators through the CTAP2 and Webauthn protocols.

Installation
------------

Before you start, make sure you have `Symfony UX configured in your app`_.

Then install the bundle using Composer and Symfony Flex:

.. code-block:: terminal

    $ composer require web-auth/webauthn-stimulus

    # Don't forget to install the JavaScript dependencies as well and compile
    $ yarn install --force
    $ yarn encore dev

Also make sure you have at least version 3.0 of
`@symfony/stimulus-bridge`_ in your ``package.json`` file.

Usage
-----

*To be written*

The main usage of Symfony UX Webauthn is to use its Stimulus controller to initialize Webauthn:

.. code-block:: twig

    <form {{ stimulus_controller('web-auth/webauthn') }}>
        <button type="submit" {{ stimulus_action('webauthn', 'signin') }}>
            Sign in
        </button>
        <button type="submit" {{ stimulus_action('webauthn', 'signup') }}>
            Sign up
        </button>
    </form>

Backward Compatibility promise
------------------------------

This bundle aims at following the same Backward Compatibility promise as
the Symfony framework:
https://symfony.com/doc/current/contributing/code/bc.html

However it is currently considered `experimental`_,
meaning it is not bound to Symfony's BC policy for the moment.

.. _`Webauthn`: https://github.com/mattboldt/typed.js/blob/master/README.md
.. _`the Symfony UX initiative`: https://symfony.com/ux
.. _`@symfony/stimulus-bridge`: https://github.com/symfony/stimulus-bridge
.. _`Symfony UX configured in your app`: https://symfony.com/doc/current/frontend/ux.html
.. _`experimental`: https://symfony.com/doc/current/contributing/code/experimental.html
