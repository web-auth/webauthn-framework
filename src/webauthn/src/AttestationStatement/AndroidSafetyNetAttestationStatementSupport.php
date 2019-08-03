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

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use function Safe\json_decode;
use function Safe\sprintf;
use Webauthn\AuthenticatorData;
use Webauthn\CertificateToolbox;
use Webauthn\TrustPath\CertificateTrustPath;

final class AndroidSafetyNetAttestationStatementSupport implements AttestationStatementSupport
{
    /**
     * @var string|null
     */
    private $apiKey;

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var CompactSerializer
     */
    private $jwsSerializer;

    /**
     * @var JWSVerifier|null
     */
    private $jwsVerifier;

    /**
     * @var RequestFactoryInterface|null
     */
    private $requestFactory;

    /**
     * @var int
     */
    private $leeway;

    /**
     * @var int
     */
    private $maxAge;

    public function __construct(ClientInterface $client, ?string $apiKey, ?RequestFactoryInterface $requestFactory, int $leeway = 0, int $maxAge = 60000)
    {
        $this->jwsSerializer = new CompactSerializer();
        $this->apiKey = $apiKey;
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->initJwsVerifier();
        $this->leeway = $leeway;
        $this->maxAge = $maxAge;
    }

    public function name(): string
    {
        return 'android-safetynet';
    }

    public function load(array $attestation): AttestationStatement
    {
        Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['ver', 'response'] as $key) {
            Assertion::keyExists($attestation['attStmt'], $key, sprintf('The attestation statement value "%s" is missing.', $key));
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
        $trustPath = $attestationStatement->getTrustPath();
        Assertion::isInstanceOf($trustPath, CertificateTrustPath::class, 'Invalid trust path');
        $certificates = $trustPath->getCertificates();
        CertificateToolbox::checkChain($certificates);
        $parsedCertificate = openssl_x509_parse(current($certificates));
        Assertion::isArray($parsedCertificate, 'Invalid attestation object');
        Assertion::keyExists($parsedCertificate, 'subject', 'Invalid attestation object');
        Assertion::keyExists($parsedCertificate['subject'], 'CN', 'Invalid attestation object');
        Assertion::eq($parsedCertificate['subject']['CN'], 'attest.android.com', 'Invalid attestation object');

        /** @var JWS $jws */
        $jws = $attestationStatement->get('jws');
        $payload = $jws->getPayload();
        $this->validatePayload($payload, $clientDataJSONHash, $authenticatorData);

        //Check the signature
        $this->validateSignature($jws, $trustPath);

        //Check against Google service
        $this->validateUsingGoogleApi($attestationStatement);

        return true;
    }

    private function validatePayload(?string $payload, string $clientDataJSONHash, AuthenticatorData $authenticatorData): void
    {
        Assertion::notNull($payload, 'Invalid attestation object');
        $payload = JsonConverter::decode($payload);
        Assertion::isArray($payload, 'Invalid attestation object');
        Assertion::keyExists($payload, 'nonce', 'Invalid attestation object. "nonce" is missing.');
        Assertion::eq($payload['nonce'], base64_encode(hash('sha256', $authenticatorData->getAuthData().$clientDataJSONHash, true)), 'Invalid attestation object. Invalid nonce');
        Assertion::keyExists($payload, 'ctsProfileMatch', 'Invalid attestation object. "ctsProfileMatch" is missing.');
        Assertion::true($payload['ctsProfileMatch'], 'Invalid attestation object. "ctsProfileMatch" value is false.');
        Assertion::keyExists($payload, 'timestampMs', 'Invalid attestation object. Timestamp is missing.');
        Assertion::integer($payload['timestampMs'], 'Invalid attestation object. Timestamp shall be an integer.');
        $currentTime = time() * 1000;
        Assertion::lessOrEqualThan($payload['timestampMs'], $currentTime + $this->leeway, sprintf('Invalid attestation object. Issued in the future. Current time: %d. Response time: %d', $currentTime, $payload['timestampMs']));
        Assertion::lessOrEqualThan($currentTime - $payload['timestampMs'], $this->maxAge, sprintf('Invalid attestation object. Too old. Current time: %d. Response time: %d', $currentTime, $payload['timestampMs']));
    }

    private function validateSignature(JWS $jws, CertificateTrustPath $trustPath): void
    {
        $jwk = JWKFactory::createFromCertificate($trustPath->getCertificates()[0]);
        $isValid = $this->jwsVerifier->verifyWithKey($jws, $jwk, 0);
        Assertion::true($isValid, 'Invalid response signature');
    }

    private function validateUsingGoogleApi(AttestationStatement $attestationStatement): void
    {
        if (null === $this->apiKey || null === $this->requestFactory) {
            return;
        }
        $uri = sprintf('https://www.googleapis.com/androidcheck/v1/attestations/verify?key=%s', urlencode($this->apiKey));
        $requestBody = sprintf('{"signedAttestation":"%s"}', $attestationStatement->get('response'));
        $request = $this->requestFactory->createRequest('POST', $uri);
        $request = $request->withHeader('content-type', 'application/json');
        $request->getBody()->write($requestBody);

        $response = $this->client->sendRequest($request);
        $this->checkGoogleApiResponse($response);
        $responseBody = $this->getResponseBody($response);
        $responseBodyJson = json_decode($responseBody, true);
        Assertion::keyExists($responseBodyJson, 'isValidSignature', 'Invalid response.');
        Assertion::boolean($responseBodyJson['isValidSignature'], 'Invalid response.');
        Assertion::true($responseBodyJson['isValidSignature'], 'Invalid response.');
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

    private function checkGoogleApiResponse(ResponseInterface $response): void
    {
        Assertion::eq(200, $response->getStatusCode(), 'Request did not succeeded');
        Assertion::true($response->hasHeader('content-type'), 'Unrecognized response');

        foreach ($response->getHeader('content-type') as $header) {
            if (0 === mb_strpos($header, 'application/json')) {
                return;
            }
        }

        throw new InvalidArgumentException('Unrecognized response');
    }

    private function convertCertificatesToPem(array $certificates): array
    {
        foreach ($certificates as $k => $v) {
            $tmp = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
            $tmp .= chunk_split($v, 64, PHP_EOL);
            $tmp .= '-----END CERTIFICATE-----'.PHP_EOL;
            $certificates[$k] = $tmp;
        }

        return $certificates;
    }

    private function initJwsVerifier(): void
    {
        $algorithmManager = new AlgorithmManager([
            new Algorithm\RS256(), new Algorithm\RS384(), new Algorithm\RS512(),
            new Algorithm\PS256(), new Algorithm\PS384(), new Algorithm\PS512(),
            new Algorithm\ES256(), new Algorithm\ES384(), new Algorithm\ES512(),
            new Algorithm\EdDSA(),
        ]);
        $this->jwsVerifier = new JWSVerifier($algorithmManager);
    }
}
