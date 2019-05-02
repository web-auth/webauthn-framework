Webauthn Based Symfony Security Firewall
========================================

# Bundle Configuration

To use this firewall, you must have configured:

* a Public Key Credential Source Repository,
* a User Entity Repository,
* a request profile
* a PSR-7 message factory service

Additionally, your Symfony application must have a [user provider service]().

The Public Key Credential Source and User Entity Repositories are described in the [bundle configuration page](./index.md).

```yaml

webauthn_json:
    credential_repository: 'App\Repository\PublicKeyCredentialSourceRepository'
    user_repository: 'App\Repository\PublicKeyCredentialUserEntityRepository'
    request_profiles:
        default: # Unique name of the profile
            rp_id: 'my-app.com' # the relying party ID
            challenge_length: 32 # in bytes
            timeout: 60000 # = 60 seconds
            user_verification: !php/const Webauthn\AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
``` 

## PSR-7 Message Factory Service

The message factory service is needed to convert Symfony Requests into Psr7 Requests.
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
```

# Firewall Configuration

Hereafter the minimal configuration for the firewall.

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                profile: 'default' # required. See above
                http_message_factory: 'Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory' # required. See above

    access_control:
        - { path: ^/login,  roles: IS_AUTHENTICATED_ANONYMOUSLY, requires_channel: https }
```

# User Authentication

## Get Options

Prior to the authentication of the user, you must get a PublicKey Credential Request Options object.
To do so, send a POST request to `/login/options`.

The body of this request is a JSON object that must contain a `username` member with the name of the user being authenticated.

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

You can change that path is needed:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                options_path: /security/authentication/options

    access_control:
        - { path: ^/security,  roles: IS_AUTHENTICATED_ANONYMOUSLY, requires_channel: https }

```


## User Assertion

When the user touched is security device, you will receive a response from it.
You just have to send a POST request to `/login`.

The body of this request is the response of the security device.

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

You can change that path is needed:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                login_path: /security/authentication/login

    access_control:
        - { path: ^/security,  roles: IS_AUTHENTICATED_ANONYMOUSLY, requires_channel: https }
```

## Handlers

You can customize the responses returned by the firewall by using a custom handler.
This could be useful when using an access token manager (e.g. [LexikJWTAuthenticationBundle](https://github.com/lexik/LexikJWTAuthenticationBundle))
or to add other parameters to the response.

There are 3 types of responses and handlers:

* Request options,
* Authentication Success,
* Authentication Failure,

### Request Options Handler

This handler is called when a client sends a valid POST request to the `options_path`.
The default Request Options Handler is `Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler`.
It returns a JSON Response with the Public Key Credential Request Options objects in its body. 

Your custom handler have to implement the interface `Webauthn\Bundle\Security\Handler\RequestOptionsHandler`
and be declared as a container service.

When done, you can set your new service in the firewall configuration:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                request_options_handler: 'App\Handler\MyCustomRequestOptionsHandler'
```

### Authentication Success Handler

This handler is called when a client sends a valid assertion from the authenticator.
The default handler is `Webauthn\Bundle\Security\Handler\DefaultSuccessHandler`.

Your custom handler have to implement the interface `Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface`
and be declared as a container service.

When done, you can set your new service in the firewall configuration:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                success_handler: 'App\Handler\MyCustomAuthenticationSuccessHandler'
```

### Authentication Failure Handler

This handler is called when an error occurred during the authentication process.
The default handler is `Webauthn\Bundle\Security\Handler\DefaultFailureHandler`.

Your custom handler have to implement the interface `Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface`
and be declared as a container service.

When done, you can set your new service in the firewall configuration:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                failure_handler: 'App\Handler\MyCustomAuthenticationFailureHandler'
```

## Request Options Storage

Webauthn authentication is a 2 steps round trip authentication:

* Request options issuance
* Authenticator assertion verification

It is needed to store the request options and the user entity associated to it to verify the authenticator assertions.

By default, the firewall uses `Webauthn\Bundle\Security\Storage\SessionStorage`.
This storage system stores the data in a session.

If this behaviour does not fit on your needs (e.g. you want to use a database, REDIS…),
you can implement a custom data storage for that purpose.
Your custom storage system have to implement `Webauthn\Bundle\Security\Storage\RequestOptionsStorage`
and declared as a container service.

When done, you can set your new service in the firewall configuration:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                request_options_storage: 'App\Handler\MyCustomRequestOptionsStorage'
```

# Fake User Entities And Credentials

Let’s imagine a malicious application that sends several POST requests to the options path with different usernames.
The firewall will respond with an error 401 if the username does not exist or generate a `PublicKeyCredentialRequestOptions` object if it does.
Thus the malicious app will be capable of establishing a username list and associated credentials.

To avoid that username enumeration, you can create an optional fake user provider that implements `Webauthn\Bundle\Provider\FakePublicKeyCredentialUserEntityProvider` and generate user entities and associate credentials on demand.
You have to ensure that, for a given username, the fake data is always the same by using a persistent storage or caching system, otherwise the malicious app could understand this is fake data.

```php
<?php
declare(strict_types=1);

namespace App\Provider;

use Faker\Factory; // See https://github.com/fzaninotto/Faker
use Psr\Cache\CacheItemPoolInterface; // See PSR 6
use Ramsey\Uuid\Uuid; // See https://github.com/ramsey/uuid
use Webauthn\Bundle\Model\PublicKeyCredentialFakeUserEntity;
use Webauthn\Bundle\Provider\FakePublicKeyCredentialUserEntityProvider;
use Webauthn\PublicKeyCredentialDescriptor;

final class PublicKeyCredentialFakeUserEntityProvider implements FakePublicKeyCredentialUserEntityProvider
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    public function __construct(CacheItemPoolInterface $cacheItemPool)
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    public function getFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity
    {
        $cacheItem = $this->cacheItemPool->getItem('FAKE_USER_ENTITIES-'.$username); //We check in the cache system
        if ($cacheItem->isHit()) { // If found, we return the data
            return $cacheItem->get();
        }

        $fakeUserEntity = $this->generateFakeUserEntityFor($username); // Otherwise we create a new fake user
        $cacheItem->set($fakeUserEntity); // We store it in the cache system
        $this->cacheItemPool->save($cacheItem);

        return $fakeUserEntity; // We return the data
    }

    public function generateFakeUserEntityFor(string $username): PublicKeyCredentialFakeUserEntity
    {
        $nbCredentials = random_int(1, 6); // We define a random number of credentials
        $credentials = [];
        for($i = 0; $i < $nbCredentials; ++$i) {
            $credentials[] = new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                random_bytes(32)
            );
        }
        $factory = Factory::create();

        return new PublicKeyCredentialFakeUserEntity(
            $username, // The username
            Uuid::uuid4()->toString(), // A random UUID
            $factory->name, // A fake name
            $credentials // The list of fake credentials
        );
    }
}
```

When done, you can set your new service in the firewall configuration:

```yaml
security:
    firewalls:
        main:
            …
            webauthn_json: # The Webauthn firewall
                …
                fake_user_entity_provider: 'App\Provider\PublicKeyCredentialFakeUserEntityProvider'
```

# Authentication Attributes

The security token returned by the firewall sets some attributes depending on the assertion and the capabilities of the authenticator.
The attributes are:

* `IS_USER_PRESENT`: the user was present during the authentication ceremony. This attribute is usually set to `true` by Webauthn authenticators
* `IS_USER_VERIFIED`: the user was verified by the authenticator. Verification may be performed by several means including biometrics ones (fingerprint, iris, facial recognition…)

You can then set constraints to the access controls.

```yaml
security:
    firewalls:
      …
    access_control:
        - { path: ^/profile,  roles: IS_AUTHENTICATED_FULLY, requires_channel: https }
        - { path: ^/admin,  roles: IS_USER_VERIFIED, requires_channel: https }
```
