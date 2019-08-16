Public Key Credential Request
=============================

Here we suppose you already have a valid Webauthn Server as described in [the Attestation page](Attestation.md).

To generate a `PublicKeyCredentialRequestOptions` object, you just need to call the method `generatePublicKeyCredentialRequestOptions`.
This object can be serialized into JSON and sent to the client.

```php
<?php

use Nyholm\Psr7\Response;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

$userEntity = new PublicKeyCredentialUserEntity('jdoe', 'unique ID', 'John Doe');
$allowedCredentials = $publicKeyCredentialSourceRepository->findAllForUserEntity($userEntity);

// The following method arguments are not mandatory. For demo only.
// However, the list of authenticators cannot be be empty if the user verification value if not "required"
$options = $server->generatePublicKeyCredentialRequestOptions(
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    $allowedCredentials
);

//Save the options somewhere (e.g. session)
//And send it to the client (JSON)
```

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


/** @var \Webauthn\Server $server */
$publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
    '_The data you receive from the authenticator…',
    $options, // Same object as above
    null, // If you know the user entity (retrieved using its username), you can pass it here
    $serverRequest
);

// The $publicKeyCredentialSource contains the Public Key Credential Source used for the authentication of the user
// If you haven’t the user entity, you can get it using the unique user handle defined in $publicKeyCredentialSource
```

When done, you can try [to authenticate you users](Assertion.md).
