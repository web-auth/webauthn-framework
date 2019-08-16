Public Key Credential Creation
==============================

The Webauthn Easy Server is a simple class that have the basic features for your application.

```php
<?php

use Webauthn\Server;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\PublicKeyCredentialRpEntity;

$rpEntity = new PublicKeyCredentialRpEntity('Webauthn Server', 'my.domain.com');
$publicKeyCredentialSourceRepository = …; //Your repository here. Must implement Webauthn\PublicKeyCredentialSourceRepository
$metadataStatementRepository = new MetadataStatementRepository();

$server = new Server(
    $rpEntity,
    $publicKeyCredentialSourceRepository,
    $metadataStatementRepository
);
```

To generate a `PublicKeyCredentialCreationOptions` object, you just need to call the method `generatePublicKeyCredentialCreationOptions`.
This object can be serialized into JSON and sent to the client.

```php
<?php

use Nyholm\Psr7\Response;
use Webauthn\PublicKeyCredentialUserEntity;

$userEntity = new PublicKeyCredentialUserEntity('jdoe', 'unique ID', 'John Doe');

$options = $server->generatePublicKeyCredentialCreationOptions($userEntity);

$response = new Response(200, ['Content-Type' => 'application/json']);
$response->getBody()->write(json_encode($options));

//Send the response
```

When the authenticator send you the computed response, you can load it and check it.
If successful, you will receive a `PublicKeyCredentialSource` object.

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


$publicKeyCredentialSource = $server->loadAndCheckAttestationResponse(
    '_The data you receive from the authenticator…',
    $options, // Same object as above
    $serverRequest
);

// The user entity and the public key credential source can now be stored using theeir repository
$publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);
$userEntityRepository->save($userEntity);
```
