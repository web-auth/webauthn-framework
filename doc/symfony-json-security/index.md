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

# Fake User Entities And Credentials

Let's imagine a malicious application that sends several POST requests to the options path with different usernames.
The firewall will respond with an error 401 if the username does not exist or generate a `PublicKeyCredentialRequestOptions` object if it does.
Thus the malicious app will be capable of establishing a a list of usernames and associated credentials.

To avoid that usernames enumeration, you have to create a fake user provider that implements `Webauthn\JsonSecurityBundle\Provider\FakePublicKeyCredentialUserEntityProvider` and generate user entities and associate credentials on demand.
You have to ensure that, for a given username, the fake data is always the same by using a persistent storage or caching system, otherwise the malicious app could understand this is fake data.

```php
<?php
declare(strict_types=1);

namespace App\Provider;

use Faker\Factory; // See https://github.com/fzaninotto/Faker
use Psr\Cache\CacheItemPoolInterface; // See PSR 6
use Ramsey\Uuid\Uuid; // See https://github.com/ramsey/uuid
use Webauthn\JsonSecurityBundle\Model\PublicKeyCredentialFakeUserEntity;
use Webauthn\JsonSecurityBundle\Provider\FakePublicKeyCredentialUserEntityProvider;
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
        $cacheItem = $this->cacheItemPool->getItem('FAKE_USER_ENTITIES/'.$username): //We check in the cache system
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
        $credential = [];
        for(int $i = 0; $i < $nbCredentials; ++$i) {
            $credential[] = new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                random_bytes(32)
            );
        }
        $factory = Factory::create();
        
        return new PublicKeyCredentialFakeUserEntity(
            $username, // The username
            Uuid::uuid4()->toString(), // A random UUID
            $factory->name, // A fake name
        );
    }
}
```

This class can now be declared as a service and set in the bundle configuration:

```yaml
webauthn_json_security:
    fake_user_entity_provider: 'App\Provider\PublicKeyCredentialFakeUserEntityProvider'
```
