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
use DateTimeImmutable;
use Http\Client\HttpClient;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\RequestFactoryInterface;
use function Safe\base64_decode;
use function Safe\json_decode;
use function Safe\sprintf;

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
     * @var CacheItemPoolInterface|null
     */
    private $cacheItemPool;

    public function __construct(HttpClient $httpClient, RequestFactoryInterface $requestFactory, string $token, ?CacheItemPoolInterface $cacheItemPool = null)
    {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->token = $token;
        $this->cacheItemPool = $cacheItemPool;
    }

    public function getMetadataStatementFor(MetadataTOCPayloadEntry $entry): MetadataStatement
    {
        if (null !== $this->cacheItemPool) {
            $cacheItem = $this->cacheItemPool->getItem('MetadataTOCPayloadntry-'.$entry->getAaguid());
            if ($cacheItem->isHit()) {
                $payload = $cacheItem->get();
            } else {
                $payload = $this->getMetadataTOCPayloadEntryFromMetadataService($entry);
                $cacheItem->set($payload);
                $this->cacheItemPool->save($cacheItem);
            }
        } else {
            $payload = $this->getMetadataTOCPayloadEntryFromMetadataService($entry);
        }
        try {
            $json = base64_decode($payload, true);
            $data = json_decode($json, true);

            return MetadataStatement::createFromArray($data);
        } catch (\Throwable $throwable) {
            throw new \InvalidArgumentException(sprintf('Unable to load the metadata statement of AAGUID "%s"', $entry->getAaguid()), $throwable->getCode(), $throwable);
        }
    }

    public function getMetadataTOCPayload(): MetadataTOCPayload
    {
        if (null !== $this->cacheItemPool) {
            $cacheItem = $this->cacheItemPool->getItem('MetadataTOCPayload');
            if ($cacheItem->isHit()) {
                $payload = $cacheItem->get();
            } else {
                $payload = $this->getMetadataTOCPayloadFromMetadataService();
                $cacheItem->set($payload);
                $this->cacheItemPool->save($cacheItem);
            }
        } else {
            $payload = $this->getMetadataTOCPayloadFromMetadataService();
        }
        $data = MetadataTOCPayload::createFromArray(json_decode($payload, true));
        $this->storeInCache($payload, $data->getNextUpdate());

        return $data;
    }

    private function storeInCache(string $payload, string $nextUpdate): void
    {
        if (null === $this->cacheItemPool) {
            return;
        }
        $expiresAt = new DateTimeImmutable($nextUpdate);
        $cacheItem = $this->cacheItemPool->getItem('MetadataTOCPayload');
        $cacheItem->set($payload);
        $cacheItem->expiresAt($expiresAt);
    }

    private function getMetadataTOCPayloadEntryFromMetadataService(MetadataTOCPayloadEntry $entry): string
    {
        $url = $entry->getUrl();
        Assertion::notNull($url, 'No URL provided for the entry');
        $uri = sprintf('%s?token=%s', $entry->getUrl(), $this->token);
        $content = $this->callMetadataService($uri);

        return $content;
    }

    private function getMetadataTOCPayloadFromMetadataService(): string
    {
        $uri = sprintf('%s/?token=%s', self::SERVICE_URI, $this->token);
        $content = $this->callMetadataService($uri);
        $payload = $this->getJwsPayload($content);

        return $payload;
    }

    private function callMetadataService(string $uri): string
    {
        $request = $this->requestFactory->createRequest('GET', $uri);
        $response = $this->httpClient->sendRequest($request);
        Assertion::eq(200, $response->getStatusCode(), sprintf('Unable to contact the server. Response code is %d', $response->getStatusCode()));

        return $response->getBody()->getContents();
    }

    private function getJwsPayload(string $token): string
    {
        $jws = (new CompactSerializer(new StandardConverter()))->unserialize($token);
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
