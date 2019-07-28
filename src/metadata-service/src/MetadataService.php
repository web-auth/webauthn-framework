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
use Base64Url\Base64Url;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function Safe\json_decode;
use function Safe\sprintf;

class MetadataService
{
    private const SERVICE_URI = 'https://mds2.fidoalliance.org';
    /**
     * @var ClientInterface
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

    public function __construct(ClientInterface $httpClient, RequestFactoryInterface $requestFactory, string $token)
    {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->token = $token;
    }

    public function getMetadataStatementFor(MetadataTOCPayloadEntry $entry): MetadataStatement
    {
        $uri = sprintf('%s?token=%s', $entry->getUrl(), $this->token);

        return $this->getMetadataStatementAt($uri, true);
    }

    public function getMetadataStatementAt(string $uri, bool $isBase64UrlEncoded, ?ClientInterface $client = null): MetadataStatement
    {
        $payload = $this->callMetadataService($uri, $client);
        $json = $isBase64UrlEncoded ? Base64Url::decode($payload) : $payload;
        $data = json_decode($json, true);

        return MetadataStatement::createFromArray($data);
    }

    public function getMetadataTOCPayloadAt(string $uri, ?ClientInterface $client = null): MetadataTOCPayload
    {
        $content = $this->callMetadataService($uri, $client);
        $payload = $this->getJwsPayload($content);

        return MetadataTOCPayload::createFromArray(json_decode($payload, true));
    }

    public function getMetadataTOCPayload(): MetadataTOCPayload
    {
        $uri = sprintf('%s/?token=%s', self::SERVICE_URI, $this->token);

        return $this->getMetadataTOCPayloadAt($uri);
    }

    private function callMetadataService(string $uri, ?ClientInterface $client): string
    {
        $client = $client ?? $this->httpClient;
        $request = $this->requestFactory->createRequest('GET', $uri);
        $response = $client->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode(), sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));

        return $response->getBody()->getContents();
    }

    private function getJwsPayload(string $token): string
    {
        $jws = (new CompactSerializer())->unserialize($token);
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

        return $jws->getPayload();
    }
}
