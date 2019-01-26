<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use Http\Client\HttpClient;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Webauthn\AuthenticatorData;
use Webauthn\TrustPath\CertificateTrustPath;

final class AndroidSafetyNetAttestationStatementSupport implements AttestationStatementSupport
{
    /**
     * @var string
     */
    private $apiKey;
    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;
    /**
     * @var HttpClient
     */
    private $client;

    /**
     * @var CompactSerializer
     */
    private $jwsSerializer;

    public function __construct(RequestFactoryInterface $requestFactory, HttpClient $client, string $apiKey)
    {
        $this->jwsSerializer = new CompactSerializer(
            new StandardConverter()
        );
        $this->apiKey = $apiKey;
        $this->requestFactory = $requestFactory;
        $this->client = $client;
    }

    public function name(): string
    {
        return 'android-safetynet';
    }

    public function load(array $attestation): AttestationStatement
    {
        Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['ver', 'response'] as $key) {
            Assertion::keyExists($attestation['attStmt'], $key, \Safe\sprintf('The attestation statement value "%s" is missing.', $key));
        }
        $jws = $this->jwsSerializer->unserialize($attestation['attStmt']['response']);
        $jwsHeader = $jws->getSignature(0)->getProtectedHeader();
        Assertion::keyExists($jwsHeader, 'x5c', 'The response in the attestation statement must contain a "x5c" header.');
        Assertion::notEmpty($jwsHeader['x5c'], 'The "x5c" parameter in the attestation statement response must contain at least one certificate.');
        $certificates = $this->convertCertificatesToPem($jwsHeader['x5c']);

        $attestation['attStmt']['jws'] = $jws;

        return AttestationStatement::createBasic(
            $this->name(),
            $attestation['attStmt'],
            new CertificateTrustPath($certificates)
        );
    }

    public function isValid(string $clientDataJSONHash, AttestationStatement $attestationStatement, AuthenticatorData $authenticatorData): bool
    {
        $uri = \Safe\sprintf('https://www.googleapis.com/androidcheck/v1/attestations/verify?key=%s', urlencode($this->apiKey));
        $requestBody = \Safe\sprintf('{"signedAttestation":"%s"}', $attestationStatement->get('response'));
        $request = $this->requestFactory->createRequest('POST', $uri);
        $request = $request->withHeader('content-type', 'application/json');
        $request->getBody()->write($requestBody);

        $response = $this->client->sendRequest($request);
        if (!$this->isResponseSuccess($response)) {
            return false;
        }
        $responseBody = $this->getResponseBody($response);
        $responseBodyJson = \Safe\json_decode($responseBody, true);
        Assertion::keyExists($responseBodyJson, 'isValidSignature', 'Invalid response.');
        Assertion::boolean($responseBodyJson['isValidSignature'], 'Invalid response.');

        return $responseBodyJson['isValidSignature'];
    }

    private function getResponseBody(ResponseInterface $response): string
    {
        $responseBody = '';
        $response->getBody()->rewind();
        do {
            $tmp = $response->getBody()->read(1024);
            if ('' === $tmp) {
                break;
            }
            $responseBody .= $tmp;
        } while (true);

        return $responseBody;
    }

    private function isResponseSuccess(ResponseInterface $response): bool
    {
        if ($response->getStatusCode() !== 200 || !$response->hasHeader('content-type')) {
            return false;
        }

        foreach ($response->getHeader('content-type') as $header) {
            if ('application/json' === mb_substr($header, 0, 16)) {
                return true;
            }
        }

        return false;
    }

    private function convertCertificatesToPem(array $certificates): array
    {
        foreach ($certificates as $k => $v) {
            $tmp = '-----BEGIN CERTIFICATE----'.PHP_EOL;
            $tmp .= chunk_split($v, 64, PHP_EOL);
            $tmp .= '-----END CERTIFICATE-----'.PHP_EOL;
            $certificates[$k] = $tmp;
        }

        return $certificates;
    }
}
