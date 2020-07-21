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

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

class DistantSingleMetadata extends SingleMetadata
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
    private $additionalHeaders;

    /**
     * @var string
     */
    private $uri;

    /**
     * @var bool
     */
    private $isBase64Encoded;

    public function __construct(string $uri, bool $isBase64Encoded, ClientInterface $httpClient, RequestFactoryInterface $requestFactory, array $additionalHeaders = [])
    {
        parent::__construct($uri, $isBase64Encoded); //Useless
        $this->uri = $uri;
        $this->isBase64Encoded = $isBase64Encoded;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->additionalHeaders = $additionalHeaders;
    }

    public function getMetadataStatement(): MetadataStatement
    {
        return MetadataStatementFetcher::fetchMetadataStatement($this->uri, $this->isBase64Encoded, $this->httpClient, $this->requestFactory, $this->additionalHeaders);
    }
}
