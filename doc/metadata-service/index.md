Metadata Service
=================

# Installation

Install the bundle with Composer:

```sh
composer require web-auth/metadata-service
```

# What Is It?

This component is able to fetch and load local or distant Metadata Statements (MDS).
These statements have to be compliant with the [FIDO Alliance specification](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html).

MDS can be within a complete structure with a [table of content](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#metadata-toc-format)
 as well as [single statements](https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json).

Manufacturers may decide to manage their own Metadata Service or provide metadata statements of their authenticators
using a custom format/protocol (e.g. [Yubico attestation and metadata](https://developers.yubico.com/U2F/Attestation_and_Metadata/)).
If you have such use case, you can create a wrapper that will convert the data in the appropriate format.

# Metadata Service

If you need to load MDS from a Metadata Service, you need to instantiate the class `Webauthn\MetadataService\MetadataService`.

The library provides class  that will retrieve the available entries and associated attestation statements.
This class needs the following services:

* The URI of the service
* A PSR-17 Factory
* A PSR-18 Http client
* Optional additional query string key/value pairs
* Optional request headers

To avoid unnecessary calls to the distant Metadata Statement services, you may also need a cache plugin.

```php
<?php

declare(strict_types=1);

use Webauthn\MetadataService\MetadataService;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Component\HttpClient\Psr18Client;

$service = new MetadataService(
    'https/:my.service.com',
    new Psr18Client,
    new Psr17Factory
);
```

# Single Statement

TO BE WRITTEN

# Custom Statement

TO BE WRITTEN

# MDS Repository

The MDS Repository handles several Metadata Services and Single Metadata objects.
You will be able to fetch a MDS using the AAGUID of the authenticator.

```php
<?php

declare(strict_types=1);

use Webauthn\MetadataService\MetadataStatementRepository;

$repository = new MetadataStatementRepository;
$repository->addSingleStatement($mySingleStatement);
$repository->addService($myMetadataStatementService);

// Tries to find the MDS associated to the given AAGUID
// If not found, the returned value is null
$mds = $repository->findOneByAAGUID('f8a011f3-8c0a-4d15-8006-17111f9edc7d');

// Tries to find the MDS associated to the given AAID
// If not found, the returned value is null
$otherMds = $repository->findOneByAAID('001D#0002');

// All MDS
$all = $repository->findAll();
```

# Symfony Bundle

If you installed the [Symfony bundle](../symfony/index.md), you can configure the bundle and inject that service into your services
or get it from the container.

When enabled, the Metadata Statement Repository is automatically injected to the Attestation Support services.
This will allow the verification of the attestation root certificates.

You may also need the MDS of an authenticator to get additional information about it.

## Configuration

This is an example of the minimal configuration for the bundle.

```yaml
webauthn:
    metadata_service:
        enabled: true
        http_client: 'httplug.client.default' #PSR-18 Client Service
        request_factory: 'Nyholm\Psr7\Factory\Psr17Factory' #PSR-17 Factory
        services:
            service1:
                uri: 'https://mds2.fidoalliance.org'
                additional_query_string_values:
                    token: '--TOKEN--'
                additional_headers:
                    X-TEST: 'A CUSTOM HEADER'
        single_statements:
            solo:
                uri: 'https://raw.githubusercontent.com/solokeys/solo/2.1.0/metadata/Solo-FIDO2-CTAP2-Authenticator.json'
                additional_headers: ~
                is_base_64: false
```

## Usage

When enabled, the public service `Webauthn\MetadataService\MetadataStatementRepository` is available.
This service is injected to all 

```php
<?php

use Webauthn\MetadataService\MetadataStatementRepository;
$metadataStatementRepository = $container->get(MetadataStatementRepository::class);
```
