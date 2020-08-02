<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use function count;
use League\Uri\Components\Query;
use League\Uri\UriString;
use LogicException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;

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

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(string $serviceUri, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalQueryStringValues = [], array $additionalHeaders = [], ?LoggerInterface $logger = null)
    {
        if (0 !== count($additionalQueryStringValues)) {
            @trigger_error('The argument "additionalQueryStringValues" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addQueryStringValues`.', E_USER_DEPRECATED);
        }
        if (0 !== count($additionalQueryStringValues)) {
            @trigger_error('The argument "additionalHeaders" is deprecated since version 3.3 and will be removed in 4.0. Please set an empty array instead and us the method `addHeaders`.', E_USER_DEPRECATED);
        }
        if (null !== $logger) {
            @trigger_error('The argument "logger" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setLogger" instead.', E_USER_DEPRECATED);
        }
        $this->serviceUri = $serviceUri;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalQueryStringValues = $additionalQueryStringValues;
        $this->additionalHeaders = $additionalHeaders;
        $this->logger = $logger ?? new NullLogger();
    }

    public function addQueryStringValues(array $additionalQueryStringValues): self
    {
        $this->additionalQueryStringValues = $additionalQueryStringValues;

        return $this;
    }

    public function addHeaders(array $additionalHeaders): self
    {
        $this->additionalHeaders = $additionalHeaders;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function getMetadataStatementFor(MetadataTOCPayloadEntry $entry, string $hashingFunction = 'sha256'): MetadataStatement
    {
        $this->logger->info('Trying to get the metadata statement for a given entry', ['entry' => $entry]);
        try {
            $hash = $entry->getHash();
            $url = $entry->getUrl();
            if (null === $hash || null === $url) {
                throw new LogicException('The Metadata Statement has not been published');
            }
            $uri = $this->buildUri($url);
            $result = MetadataStatementFetcher::fetchMetadataStatement($uri, true, $this->httpClient, $this->requestFactory, $this->additionalHeaders, $hash, $hashingFunction);
            $this->logger->info('The metadata statement exists');
            $this->logger->debug('Metadata Statement', ['mds' => $result]);

            return $result;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
    }

    public function getMetadataTOCPayload(): MetadataTOCPayload
    {
        $this->logger->info('Trying to get the metadata service TOC payload');
        try {
            $uri = $this->buildUri($this->serviceUri);
            $toc = MetadataStatementFetcher::fetchTableOfContent($uri, $this->httpClient, $this->requestFactory, $this->additionalHeaders);
            $this->logger->info('The TOC payload has been received');
            $this->logger->debug('TOC payload', ['toc' => $toc]);

            return $toc;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            throw $throwable;
        }
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
