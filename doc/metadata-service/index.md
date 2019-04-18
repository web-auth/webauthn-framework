Metadata Service
=================

# Installation

Install the bundle with Composer:

```sh
composer require web-auth/metadata-service
```

# Prepare the Metadata Service

The library provides class `Webauthn\MetadataService\MetadataService` that will retrieve the available entries and associated attestation statements.
This class needs the following services:

* The access token you received from FIDO Alliance
* A PSR-7 Request factory
* A HTTPlug client

*Note: it is highly recommended to use the [Redirect plugin](http://docs.php-http.org/en/latest/plugins/redirect.html) for the client*

You may also need the [Cache plugin](http://docs.php-http.org/en/latest/plugins/cache.html) to avoid unnecessary calls to the metadata service.

```php
<?php

declare(strict_types=1);

use Http\Client\Curl\Client;
use Http\Client\Common\PluginClient;
use Http\Client\Common\Plugin\RedirectPlugin;
use Nyholm\Psr7\Factory\Psr17Factory;
use Webauthn\MetadataService\MetadataService;

$client = new PluginClient(
    new Client(),
    [new RedirectPlugin()]
);

$metadataService = new MetadataService(
    $client,
    new Psr17Factory(),
    '--ACCESS TOKEN--'
);
$toc = $metadataService->getMetadataTOCPayload();
```

# Usage

## Table of Content and Entries

With the variable `$metadataService`, you can send calls to the FIDO Metadata Service.
You may first need to get the table of content.

If the call succeeded, the variable `$toc` will be a valid `Webauthn\MetadataService\MetadataTOCPayload` object.
Then you can the list of available entries:

```php
<?php

$toc = $metadataService->getMetadataTOCPayload();
$entries = $toc->getEntries();
```

The return value is a list of `Webauthn\MetadataService\MetadataTOCPayloadEntry` objects.

## Metadata Statements

For a given entry in the entries list, you can rretrieve the associated Metadata Statement provided by the authenticator manufacturer.


```php
<?php
$metadataStatement = $metadataService->getMetadataStatementFor($entries[0]);
```

This object details the capabilities of the authenticators, lists the root and intermediate certificates among other information.
The detail of its properties is given in [the specification](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#metadata-keys).

# Symfony Bundle

If you installed the [Symfony bundle](../symfony/index.md), you can configure the bundle and inject that service into your services
or get it from the container.

## Configuration

This is an example of the minimal configuration for the bundle.

```yaml
webauthn:
    metadata_service:
        enabled: true
        token: 'xxxxxxxxxxxxxxxx' #Metadata Service Access Token
        http_client: 'httplug.client.default' #Httplug Client Service
        request_factory: 'Nyholm\Psr7\Factory\Psr17Factory' #PSR-7 Request Factory
```

## Usage

When enabled, the public service `Webauthn\MetadataService\MetadataService` is available.
With this service, you can send requests to the metadata service as shown above.

```php
<?php

use Webauthn\MetadataService\MetadataService;
$metadataService = $container->get(MetadataService::class);
```

# Other Metadata Services

Manufacturers may decide to manage their own Metadata Services and therefore the metadata statements of their authenticators
may be available only in a dedicated repository.

The `MetadataService` class allows you to send requests to these custom services using the following methods:

* `getMetadataTOCPayloadAt(string $uri, ?HttpClient $client = null): MetadataTOCPayload`
* `getMetadataStatementAt(string $uri, bool $isBase64UrlEncoded, ?HttpClient $client = null): MetadataStatement`

The parameters are:

* `string $uri`: the URI to send the request to.
* `bool $isBase64UrlEncoded`: if the response from the metadata service is encoded in base64 (url safe), set the value to `true`.
* `HttpClient $client`: if for some reasons you need to use another client (e.g. the service requires client/user authentication), just set your custom client.
