Public Key Credential Creation
==============================

During this step, your application will send a challenge to the device.
The device will resolve this challenge by adding information and digitally signing the data.

The application will check the response from the device and get its credential ID.
This ID will be used for further authentication requests.

# Creation Request

To associate a device to a user, you need to instantiate a `U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions` object.
This object will need:

* The Relaying Party data (your application)
* The User data
* A challenge (random binary string)
* A list of supported public key parameters (at least one)
* A timeout (optional)
* A list of public key credential to exclude from the registration process (optional)
* The Authenticator Selection Criteria (e.g. user presence requirement)
* Attestation conveyance preference (optional)
* Extensions (optional)

The `PublicKeyCredentialCreationOptions` object and all objects below are designed to be easily serialized into a JSON object.
This behaviour will ease the integration of your creation options e.g. when integrated into an HTML page (see example below).

## Relaying Party Entity

The Relaying Party Entity corresponds to your application details.

It needs 
* a name (required): your application name
* an ID (optional): corresponds to the domain or sub-domain. If absent, the current domain is used.
* an icon (optional)


```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;

$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    'foo.example.com',              //ID
    null                            //Icon
);
```

The ID must be `null`, the domain or sub-domain **only** of your application.
**The scheme, port, path, user… are not allowed**.

It could be `www.sub.domain.com`, `sub.domain.com`, `domain.com` but **not** `www.sub.domain.com:1337`, `https://domain.com:443`, `sub.domain.com/index`.

## User Entity

The User Entity needs the same information as the Relaying Party plus a display name:

* a name (required): this value corresponds to the username. **This value must be unique**.
* an ID (required): this user ID. **This value must be unique**.
* a display name (required): a human-palatable name for the user account, intended only for display. For example, "Alex P. Müller" or "田中 倫".
* an icon (optional)

```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike',                          //Display name
    null                                    //Icon
);
```

## Challenge

The challenge is a random string that contains enough entropy to make guessing them infeasible.
It should be at least 16 bytes long.

```php
<?php

$challenge = random_bytes(32); // 32 bytes challenge
```

## Public Key Credential Parameters

The Public Key Credential Parameters is a list of allowed algorithms and key types.
This list must contain at least one element.

The order is very important. The authentication device will consider the first one in the list as the most important one.


```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;

$publicKeyCredentialParameters = [
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_RS256),
];
```

**Please note that at the moment the algorithms supported by this library are very limited.**
**We recommend to use only ES256.**

## Timeout

You can specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
This is treated as a hint, and may be overridden by the client.

We recommend to set 60 seconds (60000 milliseconds).

## Excluded Credentials

The user trying to register a device may have registered other devices.
To limit the creation of multiple credentials for the same account on a single authenticator, you can then ignore these devices.

The usage `U2FAuthentication\Fido2\PublicKeyCredentialDescriptor` class is described in the response processing section.

```php
<?php
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;

$excludedDevice = new PublicKeyCredentialDescriptor(
    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,      // Type of credential (usually 'public-key')
    $publicKeyId,                                                   // ID of the credential (given after creation process)
    [                                                               // Transport mode of the device (optional)
        PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
        PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
    ]
);

$excludedCredentials =[
    $excludedDevice
];
```

## Authenticator Selection Criteria

The `U2FAuthentication\Fido2\AuthenticatorSelectionCriteria` object is intended to select the appropriate authenticators to participate in the creation operation.

* Attachment: indicates if the device should be attached on the platform or not or if there is no requirement about it.
* Resident key: indicates if a resident key mandatory or not (default `false`).
* User presence: requirements regarding the user verification. Eligible authenticators are filtered and only capable of satisfying this requirement will interact with the user.

```php
<?php
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;

$excludedDevice = new AuthenticatorSelectionCriteria(
    AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,      // Attachment mode:
                                                                            //   * null (const AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE) - default value
                                                                            //   * 'platform' (const AUTHENTICATOR_ATTACHMENT_PLATFORM)
                                                                            //   * 'cross-platform' (const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM)
    false,                                                                  // Resident key (default=false)
    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED // User presence:
                                                                            //   * 'preferred' (const USER_VERIFICATION_REQUIREMENT_PREFERRED) - default value
                                                                            //   * 'required' (const USER_VERIFICATION_REQUIREMENT_REQUIRED)
                                                                            //   * 'discouraged' (const USER_VERIFICATION_REQUIREMENT_DISCOURAGED)
);
```

## Attestation Conveyance

This parameter specify the preference regarding the attestation conveyance during credential generation.
There are 3 possible values:

* none: the application is not interested in authenticator attestation. For example, in order to potentially avoid having to obtain user consent to relay identifying information to the Relying Party, or to save a roundtrip to an Attestation CA.
* indirect: the application prefers an attestation conveyance yielding verifiable attestation statements, but allows the client to decide how to obtain such attestation statements. The client MAY replace the authenticator-generated attestation statements with attestation statements generated by an Anonymization CA, in order to protect the user’s privacy, or to assist the application with attestation verification in a heterogeneous ecosystem. There is no guarantee that the application will obtain a verifiable attestation statement in this case. For example, in the case that the authenticator employs self attestation.
* direct: the application wants to receive the attestation statement as generated by the authenticator.

Predefined constants are available through the `U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions` class:

* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE`
* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT`
* `PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT`

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

The following example is a possible Public Key Creation page for a dummy user "@cypher-Angel-3000".

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtension;
use U2FAuthentication\Fido2\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;
use U2FAuthentication\Fido2\AuthenticatorSelectionCriteria;
use U2FAuthentication\Fido2\PublicKeyCredentialCreationOptions;
use U2FAuthentication\Fido2\PublicKeyCredentialParameters;
use U2FAuthentication\Fido2\PublicKeyCredentialRpEntity;
use U2FAuthentication\Fido2\PublicKeyCredentialUserEntity;

// RP Entity
$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    'foo.example.com',              //ID
    null                            //Icon
);

// User Entity
$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike',                          //Display name
    null                                    //Icon
);

// Challenge
$challenge = random_bytes(32);

// Public Key Credential Parameters
$publicKeyCredentialParametersList = [
    new PublicKeyCredentialParameters('public-key', PublicKeyCredentialParameters::ALGORITHM_ES256),
];

// Timeout
$timeout = 20000;

// Devices to exclude
$excludedPublicKeyDescriptors = [
    new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, 'ABCDEFGH'),
];

// Authenticator Selection Criteria (we used default values)
$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();

// Extensions
$extensions = new AuthenticationExtensionsClientInputs();
$extensions->add(new AuthenticationExtension('loc', true));

$publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
    $rpEntity,
    $userEntity,
    $challenge,
    $publicKeyCredentialParametersList,
    $timeout,
    $excludedPublicKeyDescriptors,
    $authenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    $extensions
);
?>

<html>
    <head>
        <meta charset="UTF-8" />
        <title>Request</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($publicKeyCredentialCreationOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

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

**It is important to store this request (variable `$publicKeyCredentialCreationOptions`) in the session for the next step; this object will be needed to check the response from the device.**

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
* Verify the loaded data against the creation options set above

## Prerequisites

You will need the following components before loading or verifying the data:

* A credential repository
* A CBOR Decoder (binary format used by the Webauthn protocol)
* An Attestation Statement Support Manager and at least one Attestation Statement Support object
* An Attestation Object Loader
* A Public Key Credential Loader
* An Authenticator Attestation Response Validator

That’s a lot off classes! But don’t worry, as their configuration is the same for all your application, you just have to set them once.

### Credential Repository

This repository must implement `U2FAuthentication\Fido2\CredentialRepository`.
It will retrieve the credentials, key IDs and update devices counters when needed.

You can implement the mrequired methods the way you want: Doctrine ORM, file storage…

### CBOR Decoder

Don’t panic! This library uses [`spomky-labs/cbor-php`](https://github.com/Spomky-Labs/cbor-php) and there is nothing complicated to do:

```php
<?php

declare(strict_types=1);

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;

$decoder = new Decoder(new OtherObjectManager(), new TagObjectManager());
```

That’s all!

### Attestation Statement Support Manager

At the moment, only 3 Attestation Statement types are supported:

* none
* fido-u2f
* packed

We highly recommend to use them all.

You just have to instantiate the classes and add these to the dedicated manager (`U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager` class).

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AttestationStatement\AttestationStatementSupportManager;
use U2FAuthentication\Fido2\AttestationStatement\FidoU2FAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\NoneAttestationStatementSupport;
use U2FAuthentication\Fido2\AttestationStatement\PackedAttestationStatementSupport;

$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
$attestationStatementSupportManager->add(new PackedAttestationStatementSupport());
```

*Please note that at the moment the `packed` attestation statement does not support ECDAA and self attestation statements.

### Attestation Object Loader

This object will load the Attestation statements received from the devices.
It will need the CBOR Decoder as dependency.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AttestationStatement\AttestationObjectLoader;

$attestationObjectLoader = new AttestationObjectLoader($decoder);
```

### Public Key Credential Loader

This object will load the Public Key using from the Attestation Object.
It will need the CBOR Decoder an dependency.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\PublicKeyCredentialLoader;

$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);
```

### Authenticator Attestation Response Validator

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAttestationResponseValidator;

$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
    $attestationStatementSupportManager,
    $credentialRepository
);
```

## Data Loading

Now that all components are set, we can load the data we receive using the *Public Key Credential Loader* service (variable `$publicKeyCredential`).

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

1. The authenticator response is of type `AuthenticatorAttestationResponse`
2. This response is valid.

The first is easy to perform:

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\AuthenticatorAttestationResponse;

$authenticatorAttestationResponse = $publicKeyCredential->getResponse();
if (!$authenticatorAttestationResponse instanceof AuthenticatorAttestationResponse) {
    //e.g. process here with a redirection to the public key creation page. 
}
```

The second step is the verification against the Public Key Creation Options we created earlier.

The Authenticator Attestation Response Validator service (variable `$authenticatorAttestationResponseValidator`)
will check everything for you: challenge, origin, attestation statement and much more.

```php
<?php

declare(strict_types=1);

$authenticatorAttestationResponseValidator->check(
    $authenticatorAttestationResponse,
    $publicKeyCredentialCreationOptions
);
```

If the Relaying Party Entity set in the `$publicKeyCredentialCreationOptions` have no ID (i.e. uses the current domain),
you MUST set it here as third argument.

```php
<?php

declare(strict_types=1);

$authenticatorAttestationResponseValidator->check(
    $authenticatorAttestationResponse,
    $publicKeyCredentialCreationOptions,
    'foo.example.com'
);
```

If no exception is thrown, the response is valid and you can store and associate those to the user:

* The Public Key Descriptor
* The Attested Credential Data

The way you store and associate these objects to the user is out of scope of this library.

These to objects implement `\JsonSerializable` and have a static method `createFromJson(string $json)`.
This will allow you to serialize the objects into JSON and easily go back an object.

### Public Key Descriptor

The public key descriptor is an instance of `U2FAuthentication\Fido2\PublicKeyCredentialDescriptor`.
This object can be retrieved using the method `$publicKeyCredential->getPublicKeyCredentialDescriptor()`.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\PublicKeyCredential;


/** PublicKeyCredential $publicKeyCredential */
$publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
```

You can limit the transportation mode of this credential by indicating the allowed transports for this descriptor.
In the following example, the device can only be used through Bluetooth LE or USB

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\PublicKeyCredential;
use U2FAuthentication\Fido2\PublicKeyCredentialDescriptor;


/** PublicKeyCredential $publicKeyCredential */
$publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor([
    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE,
    PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB,
]);
```

Possible transports are:

* `PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_BLE`: Bluetooth Low Energy (BLE)
* `PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_USB`: USB
* `PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_INTERNAL`: internal (embed device)
* `PublicKeyCredentialDescriptor::AUTHENTICATOR_TRANSPORT_NFC`: NFC (Near Field Communication)

**Be careful when using transport values: if you select a wrong mode, the device won’t be usable if used with another mode.**

### Attested Credential Data

The attested credential data is an instance of `U2FAuthentication\Fido2\AttestedCredentialData`.
It carries the public keys associated to the Public Key Credential Descriptor.
This object can be retrieved using the method `$publicKeyCredential$authenticatorAttestationResponse->getAttestationObject()->getAuthData()->getAttestedCredentialData()`.

```php
<?php

declare(strict_types=1);

use U2FAuthentication\Fido2\PublicKeyCredential;

/** PublicKeyCredential $publicKeyCredential */
$attestedCredentialData = $publicKeyCredential->getResponse()->getAttestationObject()->getAuthData()->getAttestedCredentialData();
```

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
use U2FAuthentication\Fido2\AuthenticatorAttestationResponse;
use U2FAuthentication\Fido2\AuthenticatorAttestationResponseValidator;
use U2FAuthentication\Fido2\PublicKeyCredentialLoader;


// Retrieve the PublicKeyCredentialCreationOptions object created earlier
$publicKeyCredentialCreationOptions = /** This data depends on the way you store it */;

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

// Authenticator Attestation Response Validator
$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
    $attestationStatementSupportManager,
    $credentialRepository
);

try {
    // Load the data
    $publicKeyCredential = $publicKeyCredentialLoader->load($data);
    $response = $publicKeyCredential->getResponse();
    
    // Check if the response is an Authenticator Attestation Response
    if (!$response instanceof AuthenticatorAttestationResponse) {
        throw new \RuntimeException('Not an authenticator attestation response');
    }

    // Check the response against the request
    $authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions);
    // If you did not set an application ID (i.e. the domain) to the PublicKeyCredentialRpEntity, you MUST set it here
    //$authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, 'foo.example.com');
} catch (\Throwable $exception) {
    ?>
    <html>
    <head>
        <title>Device registration</title>
    </head>
    <body>
    <h1>The device cannot be registered</h1>
    <p>The error message is: <?= $exception->getMessage(); ?></p>
    <p><a href="/request">Go back to registration page</a></p>
    </body>
    <?php
    exit();
}

// Everything is OK here. You can get the PublicKeyCredentialDescriptor.
$publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();

// Normally this condition should be true. Just make sure you received the credential data
$attestedCredentialData = null;
if ($response->getAttestationObject()->getAuthData()->hasAttestedCredentialData()) {
    $attestedCredentialData = $response->getAttestationObject()->getAuthData()->getAttestedCredentialData();
}

//You could also access to the following information.
$response->getAttestationObject()->getAuthData()->getSignCount(); // Current counter
$response->getAttestationObject()->getAuthData()->isUserVerified(); // Indicates if the user was verified
$response->getAttestationObject()->getAuthData()->isUserPresent(); // Indicates if the user was present
$response->getAttestationObject()->getAuthData()->hasExtensions(); // Extensions are available
$response->getAttestationObject()->getAuthData()->getExtensions(); // The extensions
$response->getAttestationObject()->getAuthData()->getReservedForFutureUse1(); //Not used at the moment
$response->getAttestationObject()->getAuthData()->getReservedForFutureUse2(); //Not used at the moment

header('Content-Type: text/html');
?>
    <html>
    <head>
        <title>Device registration</title>
    </head>
    <body>
    <h1>OK registered</h1>
    <p><a href="/login">Go to login now</a></p>
    </body>
</html>
```
