Public Key Credential Request
=============================

The Public Key Credential Request process supposes you have a user that registered at least one device.
For this user, you can get a list of Public Key Credential Descriptors with unique Public Key Credential ID.
And for each Public Key Credential ID, your repository can retrieve the Attested Credential Data and the current counter.

During this step, your application will send a challenge to the list of registered devices of the user.
The device will resolve this challenge by adding information and digitally signing the data.

The application will check the response from the device.
If the response is valid, the counter for the credential will be updated and the user can be considered as authenticated.

# Assertion Request

To perform a Public Key Credential Request, you need to instantiate a `U2FAuthentication\Fido2\PublicKeyCredentialRequestOptions` object.
This object will need:

* A challenge (random binary string)
* A timeout (optional)
* The Relaying Party ID i.e. your application domain (optional)
* A list with at least one registered Public Key Credential Descriptors
* The user presence requirement (optional)
* Extensions (optional)

The `PublicKeyCredentialRequestOptions` object and all objects below are designed to be easily serialized into a JSON object.
This behaviour will ease the integration of your request options e.g. when integrated into an HTML page (see example below).

## Challenge

The challenge is a random string that contains enough entropy to make guessing them infeasible.
It should be at least 16 bytes long.

```php
<?php

$challenge = random_bytes(32); // 32 bytes challenge
```

## Timeout

You can specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
This is treated as a hint, and may be overridden by the client.

We recommend to set 60 seconds (60000 milliseconds).

## Allowed Credentials

The user trying to authenticate must have registered at least one device.
For this user, you have to get all `U2FAuthentication\Fido2\PublicKeyCredentialDescriptor` associated to his account.

## User Verification

Eligible authenticators are filtered and only capable of satisfying this requirement will interact with the user.
Possible values are:

* `required`: this value indicates that the application requires user verification for the operation and will fail the operation if the response does not have the `UV` flag set.
* `preferred`: this value indicates that the application prefers user verification for the operation if possible, but will not fail the operation if the response does not have the `UV` flag set.
* `discouraged`: this value indicates that the application does not want user verification employed during the operation (e.g.,in the interest of minimizing disruption to the user interaction flow).

Public constants are provided by `PublicKeyCredentialDescriptor`.

* `PublicKeyCredentialDescriptor::USER_VERIFICATION_REQUIREMENT_REQUIRED`
* `PublicKeyCredentialDescriptor::USER_VERIFICATION_REQUIREMENT_PREFERRED`
* `PublicKeyCredentialDescriptor::USER_VERIFICATION_REQUIREMENT_DISCOURAGED`

## Extensions

The mechanism for generating public key credentials, as well as requesting and generating Authentication assertions,
can be extended to suit particular use cases.
Each case is addressed by defining a registration extension.

**The extensions are not yet supported by this library, but is ready to handle them.**

The Following example is totally fictive.

```php
<?php
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

$locationExtension = new AuthenticationExtension('loc', true); // Location of the device required during the creation process

$creationExtensions = new AuthenticationExtensionsClientInputs();
$creationExtensions->add($locationExtension);
```

## Example

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\PublicKeyCredentialRequestOptions;

// Extensions
$extensions = new AuthenticationExtensionsClientInputs();
$extensions->add(new AuthenticationExtension('loc', true));

// List of registered PublicKeyCredentialDescriptor classes associated to the user
$registeredPublicKeyCredentialDescriptors = …;

// Public Key Credential Request Options
$publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
    random_bytes(32),                                                           // Challenge
    60000,                                                                      // Timeout
    'foo.example.com',                                                          // Relaying Party ID
    $registeredPublicKeyCredentialDescriptors,                                  // Registered PublicKeyCredentialDescriptor classes
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED, // User verification requirement
    $extensions
);

header('Content-Type: text/html');
?>
<html>
    <head>
        <title>Login</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        publicKey.challenge = Uint8Array.from(window.atob(publicKey.challenge), c=>c.charCodeAt(0));
        publicKey.allowCredentials = publicKey.allowCredentials.map(function(data) {
            return {
                ...data,
                'id': Uint8Array.from(atob(data.id), c=>c.charCodeAt(0))
            };
        });

        navigator.credentials.get({publicKey})
            .then(data => {
                let publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        signature: arrayToBase64String(new Uint8Array(data.response.signature)),
                        userHandle: data.response.userHandle ? arrayToBase64String(new Uint8Array(data.response.userHandle)) : null
                    }
                };
                window.location = '/login_post?data='+btoa(JSON.stringify(publicKeyCredential));
            }, error => {
                console.log(error); // Example: timeout, interaction refused...
            });
    </script>
    <h1>Login</h1>
    <p>Please push the blue button!</p>
    </body>
</html>
```

# Response Handling

The way you receive this response is out of scope of this library.
In the previous example, the data is part of the query string, but it can be done through a POST request body or a request header.

What you receive must be a JSON object that looks like as follow:

```json
{
    "id":"KVb8CnwDjpgAo[…]op61BTLaa0tczXvz4JrQ23usxVHA8QJZi3L9GZLsAtkcVvWObA",
    "type":"public-key",
    "rawId":"KVb8CnwDjpgAo[…]rQ23usxVHA8QJZi3L9GZLsAtkcVvWObA==",
    "response":{
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJQbk1hVjBVTS[…]1iUkdHLUc4Y3BDSdGUifQ==",
        "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSj[…]YcGhf"
    }
}
```

There are two steps to perform with this object:

* Load the data
* Verify the loaded data against the assertion options set above

## Prerequisites

The prerequisites are the same as the ones described in the [Public Key Credential Creation](PublicKeyCredentialCreation.md) process.
The only exception is that you have to instantiate a Authenticator Assertion Response Validator.

### Authenticator Assertion Response Validator

The `U2FAuthentication\Fido2\AuthenticatorAssertionResponseValidator` class corresponds to the Authenticator Assertion Response Validator.
This class requires the Credential Repository service and the CBOR Decoder service.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAssertionResponseValidator;

$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
    $credentialIdRepository, // The Credential Repository service
    $decoder                 // The CBOR Decoder service
);
``` 

## Data Loading

This step is exactly the same as the one described in [Public Key Credential Creation](PublicKeyCredentialCreation.md) process.

```php
<?php

declare(strict_types=1);

$data = '
{
    "id":"KVb8CnwDjpgAo[…]op61BTLaa0tczXvz4JrQ23usxVHA8QJZi3L9GZLsAtkcVvWObA",
    "type":"public-key",
    "rawId":"KVb8CnwDjpgAo[…]rQ23usxVHA8QJZi3L9GZLsAtkcVvWObA==",
    "response":{
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJQbk1hVjBVTS[…]1iUkdHLUc4Y3BDSdGUifQ==",
        "attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSj[…]YcGhf"
    }
}';

$publicKeyCredential = $publicKeyCredentialLoader->load($data);
```

If no exception is thrown, the `$publicKeyCredential` is a `U2FAuthentication\Fido2\PublicKeyCredential` object.

## Response Verification

Now we have a fully loaded Public Key Credential object,
but we need now to make sure that:

1. The authenticator response is of type `AuthenticatorAssertionResponse`
2. This response is valid.

The first is easy to perform:

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAssertionResponse;

$authenticatorAssertionResponse = $publicKeyCredential->getResponse();
if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
    //e.g. process here with a redirection to the public key login/MFA page. 
}
```

The second step is the verification against the Public Key Assertion Options we created earlier.

The Authenticator Assertion Response Validator service (variable `$authenticatorAssertionResponseValidator`)
will check everything for you.

```php
<?php

declare(strict_types=1);

$authenticatorAssertionResponse->check(
    $authenticatorAssertionResponse,
    $publicKeyCredentialRequestOptions
);
```

If the Relaying Party ID is not set in the `$publicKeyCredentialRequestOptions` (i.e. uses the current domain),
you MUST set it here as third argument.

```php
<?php

declare(strict_types=1);

$authenticatorAssertionResponse->check(
    $authenticatorAssertionResponse,
    $publicKeyCredentialRequestOptions,
    'foo.example.com'
);
```

If no exception is thrown, the response is valid and you can continue the authentication of the user:

## Example

```php
<?php

declare(strict_types=1);

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;
use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\PackedAttestationStatementSupport;
use U2FAuthentication\Fido2\AuthenticatorAssertionResponseValidator;
use U2FAuthentication\Fido2\PublicKeyCredentialLoader;


// Retrieve the Options passed to the device
$publicKeyCredentialRequestOptions = /** This data depends on the way you store it */;

// Retrieve de data sent by the device
$data = /** This step depends on the way you transmit the data */;

// Create a CBOR Decoder object
$otherObjectManager = new OtherObjectManager();
$tagObjectManager = new TagObjectManager();
$decoder = new Decoder($tagObjectManager, $otherObjectManager);

// Attestation Statement Support Manager
$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
$attestationStatementSupportManager->add(new PackedAttestationStatementSupport());

// Attestation Object Loader
$attestationObjectLoader = new AttestationObjectLoader($decoder);

// Public Key Credential Loader
$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

// Credential Repository
$credentialRepository = /** The Credential Repository of your application */;

// Authenticator Assertion Response Validator
$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
  $credentialIdRepository,
  $decoder
);

try {
    // Load the data
    $publicKeyCredential = $publicKeyCredentialLoader->load($data);
    $response = $publicKeyCredential->getResponse();
    
    // Check if the response is an Authenticator Assertion Response
    if (!$response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Not an authenticator assertion response');
    }
    
    // Check the response against the request
    $authenticatorAssertionResponseValidator->check($publicKeyCredential->getRawId(), $publicKeyCredential->getResponse(), $publicKeyCredentialRequestOptions);
    // If you did not set an application ID (i.e. the domain), you MUST set it here
    //$authenticatorAssertionResponseValidator->check($publicKeyCredential->getRawId(), $publicKeyCredential->getResponse(), $publicKeyCredentialRequestOptions, 'foo.example.com');
    ?>
        <html>
        <head>
            <title>Login</title>
        </head>
        <body>
            <h1>OK logged in!</h1>
        </body>
    </html>
    <?php
} catch (\Throwable $throwable) {
    ?>
    <html>
    <head>
        <title>Login</title>
    </head>
    <body>
        <h1>Something went wrong!</h1>
        <p>The error message is: <?= $throwable->getMessage(); ?></p>
        <p><a href="/login">Go back to login page</a></p>
    </body>
    </html>
    <?php
}
```
