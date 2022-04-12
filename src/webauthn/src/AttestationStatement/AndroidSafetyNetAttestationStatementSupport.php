<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Assert\Assertion;
use InvalidArgumentException;
use Jose\Component\Core\Algorithm as AlgorithmInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use const JSON_THROW_ON_ERROR;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Webauthn\AuthenticatorData;
use Webauthn\CertificateToolbox;
use Webauthn\TrustPath\CertificateTrustPath;

final class AndroidSafetyNetAttestationStatementSupport implements AttestationStatementSupport
{
    private ?string $apiKey = null;

    private ?ClientInterface $client = null;

    private readonly CompactSerializer $jwsSerializer;

    private ?JWSVerifier $jwsVerifier = null;

    private ?RequestFactoryInterface $requestFactory = null;

    private int $leeway = 0;

    private int $maxAge = 60000;

    public function __construct()
    {
        if (! class_exists(RS256::class)) {
            throw new RuntimeException(
                'The algorithm RS256 is missing. Did you forget to install the package web-token/jwt-signature-algorithm-rsa?'
            );
        }
        if (! class_exists(JWKFactory::class)) {
            throw new RuntimeException(
                'The class Jose\Component\KeyManagement\JWKFactory is missing. Did you forget to install the package web-token/jwt-key-mgmt?'
            );
        }
        $this->jwsSerializer = new CompactSerializer();
        $this->initJwsVerifier();
    }

    public static function create(): self
    {
        return new self();
    }

    public function enableApiVerification(
        ClientInterface $client,
        string $apiKey,
        RequestFactoryInterface $requestFactory
    ): self {
        $this->apiKey = $apiKey;
        $this->client = $client;
        $this->requestFactory = $requestFactory;

        return $this;
    }

    public function setMaxAge(int $maxAge): self
    {
        $this->maxAge = $maxAge;

        return $this;
    }

    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;

        return $this;
    }

    public function name(): string
    {
        return 'android-safetynet';
    }

    /**
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        Assertion::keyExists($attestation, 'attStmt', 'Invalid attestation object');
        foreach (['ver', 'response'] as $key) {
            Assertion::keyExists(
                $attestation['attStmt'],
                $key,
                sprintf('The attestation statement value "%s" is missing.', $key)
            );
            Assertion::notEmpty(
                $attestation['attStmt'][$key],
                sprintf('The attestation statement value "%s" is empty.', $key)
            );
        }
        $jws = $this->jwsSerializer->unserialize($attestation['attStmt']['response']);
        $jwsHeader = $jws->getSignature(0)
            ->getProtectedHeader()
        ;
        Assertion::keyExists(
            $jwsHeader,
            'x5c',
            'The response in the attestation statement must contain a "x5c" header.'
        );
        Assertion::notEmpty(
            $jwsHeader['x5c'],
            'The "x5c" parameter in the attestation statement response must contain at least one certificate.'
        );
        $certificates = $this->convertCertificatesToPem($jwsHeader['x5c']);
        $attestation['attStmt']['jws'] = $jws;

        return AttestationStatement::createBasic(
            $this->name(),
            $attestation['attStmt'],
            new CertificateTrustPath($certificates)
        );
    }

    public function isValid(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        $trustPath = $attestationStatement->getTrustPath();
        Assertion::isInstanceOf($trustPath, CertificateTrustPath::class, 'Invalid trust path');
        $certificates = $trustPath->getCertificates();
        $firstCertificate = current($certificates);
        Assertion::string($firstCertificate, 'No certificate');

        $parsedCertificate = openssl_x509_parse($firstCertificate);
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

    private function validatePayload(
        ?string $payload,
        string $clientDataJSONHash,
        AuthenticatorData $authenticatorData
    ): void {
        Assertion::notNull($payload, 'Invalid attestation object');
        $payload = JsonConverter::decode($payload);
        Assertion::isArray($payload, 'Invalid attestation object');
        Assertion::keyExists($payload, 'nonce', 'Invalid attestation object. "nonce" is missing.');
        Assertion::eq(
            $payload['nonce'],
            base64_encode(hash('sha256', $authenticatorData->getAuthData() . $clientDataJSONHash, true)),
            'Invalid attestation object. Invalid nonce'
        );
        Assertion::keyExists($payload, 'ctsProfileMatch', 'Invalid attestation object. "ctsProfileMatch" is missing.');
        Assertion::true($payload['ctsProfileMatch'], 'Invalid attestation object. "ctsProfileMatch" value is false.');
        Assertion::keyExists($payload, 'timestampMs', 'Invalid attestation object. Timestamp is missing.');
        Assertion::integer($payload['timestampMs'], 'Invalid attestation object. Timestamp shall be an integer.');
        $currentTime = time() * 1000;
        Assertion::lessOrEqualThan(
            $payload['timestampMs'],
            $currentTime + $this->leeway,
            sprintf(
                'Invalid attestation object. Issued in the future. Current time: %d. Response time: %d',
                $currentTime,
                $payload['timestampMs']
            )
        );
        Assertion::lessOrEqualThan(
            $currentTime - $payload['timestampMs'],
            $this->maxAge,
            sprintf(
                'Invalid attestation object. Too old. Current time: %d. Response time: %d',
                $currentTime,
                $payload['timestampMs']
            )
        );
    }

    private function validateSignature(JWS $jws, CertificateTrustPath $trustPath): void
    {
        $jwk = JWKFactory::createFromCertificate($trustPath->getCertificates()[0]);
        $isValid = $this->jwsVerifier?->verifyWithKey($jws, $jwk, 0);
        Assertion::true($isValid, 'Invalid response signature');
    }

    private function validateUsingGoogleApi(AttestationStatement $attestationStatement): void
    {
        if ($this->client === null || $this->apiKey === null || $this->requestFactory === null) {
            return;
        }
        $uri = sprintf(
            'https://www.googleapis.com/androidcheck/v1/attestations/verify?key=%s',
            urlencode($this->apiKey)
        );
        $requestBody = sprintf('{"signedAttestation":"%s"}', $attestationStatement->get('response'));
        $request = $this->requestFactory->createRequest('POST', $uri);
        $request = $request->withHeader('content-type', 'application/json');
        $request->getBody()
            ->write($requestBody)
        ;

        $response = $this->client->sendRequest($request);
        $this->checkGoogleApiResponse($response);
        $responseBody = $this->getResponseBody($response);
        $responseBodyJson = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
        Assertion::keyExists($responseBodyJson, 'isValidSignature', 'Invalid response.');
        Assertion::boolean($responseBodyJson['isValidSignature'], 'Invalid response.');
        Assertion::true($responseBodyJson['isValidSignature'], 'Invalid response.');
    }

    private function getResponseBody(ResponseInterface $response): string
    {
        $responseBody = '';
        $response->getBody()
            ->rewind()
        ;
        do {
            $tmp = $response->getBody()
                ->read(1024)
            ;
            if ($tmp === '') {
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
            if (mb_strpos($header, 'application/json') === 0) {
                return;
            }
        }

        throw new InvalidArgumentException('Unrecognized response');
    }

    /**
     * @param string[] $certificates
     *
     * @return string[]
     */
    private function convertCertificatesToPem(array $certificates): array
    {
        foreach ($certificates as $k => $v) {
            $certificates[$k] = CertificateToolbox::fixPEMStructure($v);
        }

        return $certificates;
    }

    private function initJwsVerifier(): void
    {
        $algorithmClasses = [
            RS256::class, RS384::class, RS512::class,
            PS256::class, PS384::class, PS512::class,
            ES256::class, ES384::class, ES512::class,
            EdDSA::class,
        ];
        /** @var AlgorithmInterface[] $algorithms */
        $algorithms = [];
        foreach ($algorithmClasses as $algorithm) {
            if (class_exists($algorithm)) {
                /** @var AlgorithmInterface $algorithm */
                $algorithms[] = new $algorithm();
            }
        }
        $algorithmManager = new AlgorithmManager($algorithms);
        $this->jwsVerifier = new JWSVerifier($algorithmManager);
    }
}
