Webauthn Symfony Security Bundle
================================
----

<p align="center">:warning::warning::warning:</p>

**This bundle is deprecated in v1.2 and will be removed in v2.0**
**Please use te firewall provided in the main Symfony bundle**

<p align="center">:warning::warning::warning:</p>


# Installation

Install the bundle with Composer:

```sh
composer require web-auth/webauthn-symfony-security-bundle
```

If you are using Symfony Flex then the bundle will automatically be installed.
Otherwise you need to add it in your `AppKernel.php` file:

```php
<?php
// app/AppKernel.php

public function registerBundles()
{
    $bundles = [
        // ...
        new Webauthn\SecurityBundle\WebauthnSecurityBundle(),
    ];
}
```

# Bundle Configuration

The bundle needs a HTTP message factory service to convert Symfony Requests into Psr7 Requests.
We recommend you to install [nyholm/psr7](https://github.com/Nyholm/psr7) or any other library compatible with [the Symfony Psr7 bridge](https://symfony.com/doc/current/components/psr7.html).

Hereafter the bundle configuration using the library above.

```yaml
services:
    Nyholm\Psr7\Factory\Psr17Factory:
        public: false
    Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory:
        public: false
        arguments:
            - '@Nyholm\Psr7\Factory\Psr17Factory'
            - '@Nyholm\Psr7\Factory\Psr17Factory'
            - '@Nyholm\Psr7\Factory\Psr17Factory'
            - '@Nyholm\Psr7\Factory\Psr17Factory'
            - 
webauthn_security:
    http_message_factory: 'Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory'
```

# Firewall Configuration

In the following example, we consider you already have a Public Key Credential Source Repository, a User Repository
and user provider.

```yaml
security:
    providers:
        default:
            id: 'App\Security\UserProvider'

    firewalls:
        main:
            …
            webauthn: # The Webauthn firewall
                login_path: /login
                login_check_path: /login
                assertion_path: /login/assertion
                assertion_check_path: /login/assertion
                abort_path: /login/abort

    access_control:
        - { path: ^/login,  roles: IS_AUTHENTICATED_ANONYMOUSLY, requires_channel: https }

```