Webauthn Symfony Json Security Bundle
=====================================

# Installation

Install the bundle with Composer:

```sh
composer require web-auth/webauthn-symfony-json-security-bundle
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
        new Webauthn\JsonSecurityBundle\WebauthnJsonSecurityBundle(),
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
webauthn_json_security:
    http_message_factory: 'Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory'
```

# Bundle Configuration

To use this firewall, you must have configured:

* a Public Key Credential Source Repository,
* a User Entity Repository,
* a request profile

Additionally, your Symfony application must have a user provider service.

```yaml

webauthn:
    credential_repository: 'App\Repository\PublicKeyCredentialSourceRepository'
    user_repository: 'App\Repository\PublicKeyCredentialUserEntityRepository'
    request_profiles:
        default: # Unique name of the profile
            rp_id: 'my-app.com' # the relying party ID
            challenge_length: 32 # in bytes
            timeout: 60000 # = 60 seconds
            user_verification: !php/const Webauthn\AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
``` 

# Firewall Configuration

In the following example, we consider you already have user provider.

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                profile: 'default' # required. See above
                login_path: /login # default
                options_path: /login/options # default
                session_parameter: 'WEBAUTHN_PUBLIC_KEY_REQUEST_OPTIONS' # default

    access_control:
        - { path: ^/login,  roles: IS_AUTHENTICATED_ANONYMOUSLY, requires_channel: https }

```

# User Authentication

## Get Options

Prior to the authentication of the user, you must get PublicKey Credential Request Options.
To do so, send a POST request to the `options_path` configured above. The body of this request is a JSON object that
must contain a `username` member with the name of the user being authenticated.

**It is mandatory to set the Content-Type header to `application/json`**.

Example:
--------

```js
fetch('/login/options', {
    method  : 'POST',
    credentials : 'same-origin',
    headers : {
        'Content-Type' : 'application/json'
    },
    body: JSON.stringify({
        "username": "johndoe@example.com"
    })
}).then(function (response) {
    return response.json();
}).then(function (json) {
    console.log(json);
}).catch(function (err) {
    console.log({ 'status': 'failed', 'error': err });
})
```

In case of success, you receive a valid [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn/#assertion-options) as per the Webauthn specification.
You can then ask the user to interact with its security devices to be authenticated.

## User Assertion

When the user touched is security device, you will receive a response from it.
You just have to send a POST request to the `login_path` configured above. The body of this request is the response of the security device.

**It is mandatory to set the Content-Type header to `application/json`**.

Example:
--------

```js
fetch('/assertion/result', {
    method  : 'POST',
    credentials : 'same-origin',
    headers : {
        'Content-Type' : 'application/json'
    },
    body: //put the security device response here
}).then(function (response) {
    return response.json();
}).then(function (json) {
    console.log(json);
}).catch(function (err) {
    console.log({ 'status': 'failed', 'error': err });
})
```
