Public Key Credential Request
=============================

Here we suppose you already have a valid Webauthn Server as described in [the Attestation page](Attestation.md).

To generate a `PublicKeyCredentialRequestOptions` object, you just need to call the method `generatePublicKeyCredentialRequestOptions`.
This object can be serialized into JSON and sent to the client.

# Authentication Options

## Authentication With User Entity

In general, to authenticate your user you will ask them for their username first.
With this username, you will find the associated `Webauthn\PublicKeyCredentialUserEntity`.
And with the user entity you will get all associated Public Key Credential Source objects.

The credential list is used to build the Public Key Credential Request Options.
The user entity will be used later on.

```php
<?php

use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;use Webauthn\PublicKeyCredentialUserEntity;

// UseEntity found using the username.
$userEntity = new PublicKeyCredentialUserEntity('jdoe', 'unique ID', 'John Doe');

// Associated authenticators
$credentialSources = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);
$allowedCredentials = array_map(function (PublicKeyCredentialSource $credential) {
return $credential->getPublicKeyCredentialDescriptor();
}, $credentialSources);

// The following method arguments are not mandatory. For demo only.
// However, the list of authenticators cannot be be empty if the user verification value if not "required"
$options = $server->generatePublicKeyCredentialRequestOptions(
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    $allowedCredentials
);

//Save the options somewhere (e.g. session) and the user entity
//And send it to the client (JSON)
```

## Authentication Without User Entity

It is possible to authenticate your users without username.
This behaviour is only possible with FIDO2 authenticators and the following conditions:

* During the registration ceremony, a Resident Key was created (see Authenticator Selection Criteria in [Public Key Credential Creation](Attestation.md)),
* The user authentication is required.

```php
<?php

use Webauthn\PublicKeyCredentialRequestOptions;

$options = $server->generatePublicKeyCredentialRequestOptions(
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
);
```

# Authentication Response

When the authenticator send you the computed response, you can load it and check it.
If successful, the user is correctly authenticated.

In the example below, we use `nyholm/psr7-server` to get the PSR-7 request.
```php
<?php

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;

$psr17Factory = new Psr17Factory();
$creator = new ServerRequestCreator(
    $psr17Factory, // ServerRequestFactory
    $psr17Factory, // UriFactory
    $psr17Factory, // UploadedFileFactory
    $psr17Factory  // StreamFactory
);

$serverRequest = $creator->fromGlobals();

$publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
    '_The data you receive from the authenticator…',
    $options, // The object you saved earlier
    $userEntity, // If you know the user entity (retrieved using its username), you must pass it here. null otherwise
    $serverRequest // The PSR7 request
);

// The $publicKeyCredentialSource contains the Public Key Credential Source used for the authentication of the user
// If you haven’t the user entity, you can get it using the unique user handle defined in $publicKeyCredentialSource
```
