FIDO Universal 2nd Factor (U2F)
===============================

This library can handle U2F requests and responses for both registration and signature verification processes.

The registration process allows a user to register a new token. This token will compute a challenge and, if succeeded, the key handler can be associated to the user account.

The signature verification process will ask a user to sign a challenge. If the challenge is correcly signed with one of a registered key, then the user can be considered as authenticated.

# Registration

## Request Creation

The `RegistrationRequest` class will prepare the registration request for a given application ID.

```php
<?php
use U2F\RegistrationRequest;

$registrationRequest = new RegistrationRequest(
    'https://www.example.com' // Application ID. Usually the application URL
);
```

If the user requesting a registration already registered some keys, you can pass a list of
`U2F\RegisteredKey` objects as second argument

```php
<?php
use U2F\RegistrationRequest;

$registrationRequest = new RegistrationRequest(
    'https://www.example.com',
    $registeredKeys            //List of registered keys
);
```

The `$registrationRequest` can be serialized into JSON to ease its integration into a HTML page.

**It is important to store this request in the session for the next step.**
**This request object will be needed to check the response from the U2F device.**

Hereafter an example of registration page.

```php
<?php
use U2F\RegistrationRequest;

$registrationRequest = new RegistrationRequest(
    'https://www.example.com' //Application ID. Usually the application URL
);

$_SESSION['u2f_registration_request'] = $registrationRequest;
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>Key Registration</title>
    </head>
    <body>
        <h1>New key for user "FOO"</h1>
        TO BE WRITTEN
    </body>
</html> 
```

## Response Handling

The U2F device will compute the challenge sent in the previous step and will issue a registration response.
The way you receive this response is out of scope of this library. For example, it can be done through a POST request body, a request header or in the query string.

In the following examples, we consider the variable `$computedRequest` contains the raw data from the U2F device.

```php
<?php
use U2F\RegistrationResponse;

$registrationResponse = new RegistrationResponse(
    $computedRequest
);
```

If no exception is thrown, the variable `$registrationResponse` contains the loaded registration response.
This object contains a lot of useful data such as the client data or the signature, but the most important information is the registered key.

This key is a `U2F\RegisteredKey` object.

```php
<?php

$registeredKey = $registrationResponse->getRegisteredKey();
$registeredKey->getVersion(); // Returns "U2F_V2"
$registeredKey->getKeyHandler(); // Returns a U2F\KeyHandler object
$registeredKey->getPublicKey(); // Returns a U2F\ PublicKey object
$registeredKey->getPublicKeyAsPem(); // Returns the public key using the PEM format
$registeredKey->getAttestationCertificate(); // Returns the attestation certificate of the U2F device
```

We now need to check if the response is valid against the registration request.

```php
<?php
use U2F\RegistrationResponse;

$registrationRequest = $_SESSION['u2f_registration_request']; // We retreive the registration request
$registrationResponse = new RegistrationResponse(
    $computedRequest
);

$isValid = $registrationResponse->isValid($registrationRequest);
```

If the variable `$isValid` is `true`, you can safely associate the registered key to the user.

**TODO: DATA TO BE STORED SHOULD BE DESCRIBED.**

### Device Registration Restrictions

You can get the attestation certificate from the registered key object (method `$registeredKey->getAttestationCertificate()`)
and check information like the manufacturer, the manufacture date or the serial number of the device contained in the certificate.

If the manufacturer provides root certificates (devices [manufactured by Yubico](https://developers.yubico.com/U2F/Attestation_and_Metadata/)),
you can verify the attestation certificate validity.

# Signature

## Request Creation


The `SignatureRequest` class will prepare the signature request for a given application ID and registered devices.
In the following example, the variable `$registeredKeys` contains a list of `U2F\RegisteredKey` objects.

```php
<?php
use U2F\SignatureRequest;

$signatureRequest = new SignatureRequest(
    'https://www.example.com', //Application ID.
    $registeredKeys
);
```

The `$signatureRequest` can be serialized into JSON to ease its integration into a HTML page.

**It is important to store this request in the session for the next step.**
**This request object will be needed to check the response from the U2F device.**

Hereafter an example of signature page.

```php
<?php
use U2F\SignatureRequest;

$signatureRequest = new SignatureRequest(
    'https://www.example.com', //Application ID.
    $registeredKeys
);

$_SESSION['u2f_signature_request'] = $signatureRequest;
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>2nd Factor Verification</title>
    </head>
    <body>
        <h1>Please use one of your registered keys to compolete your authentication</h1>
        TO BE WRITTEN
    </body>
</html> 
```

## Response Handling

The U2F device will compute the challenge sent in the previous step and will issue a signature response.
The way you receive this response is out of scope of this library. For example, it can be done through a POST request body, a request header or in the query string.

In the following examples, we consider the variable `$computedRequest` contains the raw data from the U2F device.

```php
<?php
use U2F\SignatureResponse;

$signatureResponse = new SignatureResponse(
    $computedRequest
);
```

If no exception is thrown, the variable `$signatureResponse` contains the loaded signature response.
The device used by the user is identified using its Key Handler and can be found with the method `$signatureResponse->getKeyHandle()`.

You can now check if the response is valid against the signature request.

```php
<?php
use U2F\SignatureResponse;

$signatureRequest = $_SESSION['u2f_signature_request']; // We retreive the signature request
$signatureResponse = new SignatureResponse(
    $computedRequest
);

$isValid = $signatureResponse->isValid($signatureRequest);
```

If the variable `$isValid` is `true`, you can complete the user authentication.

### User Presence

The presence of the user may be important in your security strategy.
You can check if he/she was present during the signature process.

The method `$signatureResponse->isUserPresent()` will return `true` if present, otherwise `false`.

### Counter Support

Most of the U2F devices count the number of signatures to prevent the use of cloned devices.
We highly recommend you to enable tfe counter support for the registered keys.

For each registered devices, you have to add an additional unsigned integer field.
When registered, the counter for the device should be 0.

When the signature response is loaded, you have to get the current counter for the given key handler.
Then the counter is passed as second argument of the method `isValid`.

After verification, the counter associated to the key handler has to be updated.

```php
<?php
use U2F\SignatureResponse;

$signatureRequest = $_SESSION['u2f_signature_request']; // We retreive the signature request
$signatureResponse = new SignatureResponse(
    $computedRequest
);

//We retrieve the counter for the given key handler
//The variable $counterRepository is a fictive counter repository.
$currentCounter = $counterRepository->findCounterFor($signatureResponse->getKeyHandle());

$isValid = $signatureResponse->isValid(
    $signatureRequest, //Signature request
    $currentCounter
);

//We update the counter for that key handler
$counterRepository->updateCounterFor($signatureResponse->getKeyHandle(), $signatureResponse->getCounter());
```
