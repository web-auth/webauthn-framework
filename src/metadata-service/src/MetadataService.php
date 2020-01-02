<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use League\Uri\Components\Query;
use League\Uri\UriString;
use LogicException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

class MetadataService
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var array
     */
    private $additionalQueryStringValues;

    /**
     * @var array
     */
    private $additionalHeaders;
    /**
     * @var string
     */
    private $serviceUri;

    public function __construct(string $serviceUri, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalQueryStringValues = [], array $additionalHeaders = [])
    {
        $this->serviceUri = $serviceUri;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalQueryStringValues = $additionalQueryStringValues;
        $this->additionalHeaders = $additionalHeaders;
    }

    public function getMetadataStatementFor(MetadataTOCPayloadEntry $entry, string $hashingFunction = 'sha256'): MetadataStatement
    {
        $hash = $entry->getHash();
        $url = $entry->getUrl();
        if (null === $hash || null === $url) {
            throw new LogicException('The Metadata Statement has not been published');
        }
        $uri = $this->buildUri($url);

        return MetadataStatementFetcher::fetchMetadataStatement($uri, true, $this->httpClient, $this->requestFactory, $this->additionalHeaders, $hash, $hashingFunction);
    }

    public function getMetadataTOCPayload(): MetadataTOCPayload
    {
        $uri = $this->buildUri($this->serviceUri);

        return MetadataStatementFetcher::fetchTableOfContent($uri, $this->httpClient, $this->requestFactory, $this->additionalHeaders);
    }

    private function buildUri(string $uri): string
    {
        $parsedUri = UriString::parse($uri);
        $queryString = $parsedUri['query'];
        $query = Query::createFromRFC3986($queryString);
        foreach ($this->additionalQueryStringValues as $k => $v) {
            $query = $query->withPair($k, $v);
        }
        $parsedUri['query'] = 0 === $query->count() ? null : $query->__toString();

        return UriString::build($parsedUri);
    }
}
