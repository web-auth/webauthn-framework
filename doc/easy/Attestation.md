Public Key Credential Creation
==============================

The Webauthn Easy Server is a simple class that have the basic features for your application.

```php
<?php

use Webauthn\MetadataService\SimpleMetadataStatementRepository;use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;

$rpEntity = new PublicKeyCredentialRpEntity('Webauthn Server', 'my.domain.com');
$publicKeyCredentialSourceRepository = …; //Your repository here. Must implement Webauthn\PublicKeyCredentialSourceRepository

$server = new Server(
    $rpEntity,                            // The relaying party (your application)
    $publicKeyCredentialSourceRepository, // The credential repository
    null                                  // The metadata statement service (not used here)
);
```

To generate and send a `PublicKeyCredentialCreationOptions` object, you just need to call the method `generatePublicKeyCredentialCreationOptions`.
This method requires a `Webathn\PublicKeyCredentialUserEntity` object that represents the user you are creating or for which you want to add an authenticator.
 
The `PublicKeyCredentialCreationOptions` object returned by the method can be serialized into JSON and sent to the client.

```php
<?php

use Webauthn\PublicKeyCredentialUserEntity;

$userEntity = new PublicKeyCredentialUserEntity('jdoe', 'unique ID', 'John Doe');

$options = $server->generatePublicKeyCredentialCreationOptions($userEntity);
```

Then you need to send this object to the user.
This step depends on your application ; it can by a plain JSON object or an HTML page.

```html
<html>
    <head>
        <meta charset="UTF-8" />
        <title>Request</title>
    </head>
    <body>
    <script>
        let publicKey = "<?php echo json_encode($options, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>";

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), c=>c.charCodeAt(0));
        publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), c=>c.charCodeAt(0));
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(data) {
                return {
                    ...data,
                    'id': Uint8Array.from(window.atob(data.id), c=>c.charCodeAt(0))
                };
            });
        }

        navigator.credentials.create({publicKey})
            .then(function (data) {
                let publicKeyCredential = {

                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                    }
                };
                window.location = '/request_post?data='+btoa(JSON.stringify(publicKeyCredential));
            }, function (error) {
                console.log(error); // Example: timeout, interaction refused...
            });
    </script>
    </body>
</html>
```

When the authenticator send you the computed response (i.e. the user touched the button, fingerprint reader, submitted the PIN…), you can load it and check it.
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

// The user entity and the public key credential source can now be stored using their repository
// The Public Key Credential Source repository must implement Webauthn\PublicKeyCredentialSourceRepository
$publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);

// There is no requirement for the Public Key Credential User Entity repository
// You are free to implement the service you need. It just has to get and store Webauthn\PublicKeyCredentialUserEntity objects.
$userEntityRepository->save($userEntity);
```
