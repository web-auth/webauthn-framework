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

use Assert\Assertion;
use Http\Client\HttpClient;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Psr\Http\Message\RequestFactoryInterface;

class MetadataServiceCaller
{
    private const SERVICE_URI = 'https://mds2.fidoalliance.org';
    /**
     * @var HttpClient
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var string
     */
    private $token;
    /**
     * @var JWSLoader
     */
    private $jwsSerializer;

    public function __construct(HttpClient $httpClient, RequestFactoryInterface $requestFactory, string $token)
    {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->token = $token;
        $this->jwsSerializer = new CompactSerializer(new StandardConverter());
    }

    public function getMMetadataTOCPayload(): void//MetadataTOCPayload
    {
        $uri = \Safe\sprintf('%s/?token=%s',self::SERVICE_URI, $this->token);
        $request = $this->requestFactory->createRequest('GET', $uri);
        $response = $this->httpClient->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode(), \Safe\sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));

        $token = $response->getBody()->getContents();
        $jws = $this->jwsSerializer->unserialize($token);
        Assertion::eq(1, $jws->countSignatures(), 'Invalid response from the metadata service. Only one signature shall be present.');
        $signature = $jws->getSignature(0);
        $payload = $jws->getPayload();
        Assertion::notEmpty($payload, 'Invalid response from the metadata service. The token payload is empty.');
        $header = $signature->getProtectedHeader();
        Assertion::keyExists($header, 'alg', 'The "alg" parameter is missing.');
        Assertion::eq($header['alg'], 'ES256', 'The expected "alg" parameter value should be "ES256".');
        Assertion::keyExists($header, 'x5c', 'The "x5c" parameter is missing.');
        Assertion::isArray($header['x5c'], 'The "x5c" parameter should be an array.');
        $key = JWKFactory::createFromX5C($header['x5c']);
        $algorithm = new ES256();
        $isValid = $algorithm->verify($key, $signature->getEncodedProtectedHeader().'.'.$jws->getEncodedPayload(), $signature->getSignature());
        Assertion::true($isValid, 'Invalid response from the metadata service. The token signature is invalid.');

        dump(json_decode($payload));
    }
}
