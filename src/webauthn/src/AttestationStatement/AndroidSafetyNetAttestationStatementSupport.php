<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use function count;
use InvalidArgumentException;
use function is_array;
use function is_int;
use function is_string;
use Jose\Component\Core\Algorithm as AlgorithmInterface;
use Jose\Component\Core\AlgorithmManager;
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
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
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
        array_key_exists('attStmt', $attestation) || throw new InvalidArgumentException('Invalid attestation object');
        foreach (['ver', 'response'] as $key) {
            array_key_exists($key, $attestation['attStmt']) || throw new InvalidArgumentException(sprintf(
                'The attestation statement value "%s" is missing.',
                $key
            ));
            $attestation['attStmt'][$key] !== '' || throw new InvalidArgumentException(sprintf(
                'The attestation statement value "%s" is empty.',
                $key
            ));
        }
        $jws = $this->jwsSerializer->unserialize($attestation['attStmt']['response']);
        $jwsHeader = $jws->getSignature(0)
            ->getProtectedHeader();
        array_key_exists('x5c', $jwsHeader) || throw new InvalidArgumentException(
            'The response in the attestation statement must contain a "x5c" header.'
        );
        (is_countable($jwsHeader['x5c']) ? count($jwsHeader['x5c']) : 0) > 0 || throw new InvalidArgumentException(
            'The "x5c" parameter in the attestation statement response must contain at least one certificate.'
        );
        $certificates = $this->convertCertificatesToPem($jwsHeader['x5c']);
        $attestation['attStmt']['jws'] = $jws;

        return AttestationStatement::createAnonymizationCA(
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
        $trustPath instanceof CertificateTrustPath || throw new InvalidArgumentException('Invalid trust path');
        $certificates = $trustPath->getCertificates();
        $firstCertificate = current($certificates);
        is_string($firstCertificate) || throw new InvalidArgumentException('No certificate');

        $parsedCertificate = openssl_x509_parse($firstCertificate);
        is_array($parsedCertificate) || throw new InvalidArgumentException('Invalid attestation object');
        array_key_exists('subject', $parsedCertificate) || throw new InvalidArgumentException(
            'Invalid attestation object'
        );
        array_key_exists('CN', $parsedCertificate['subject']) || throw new InvalidArgumentException(
            'Invalid attestation object'
        );
        $parsedCertificate['subject']['CN'] === 'attest.android.com' || throw new InvalidArgumentException(
            'Invalid attestation object'
        );

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
        $payload !== null || throw new InvalidArgumentException('Invalid attestation object');
        $payload = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        array_key_exists('nonce', $payload) || throw new InvalidArgumentException(
            'Invalid attestation object. "nonce" is missing.'
        );
        $payload['nonce'] === base64_encode(
            hash('sha256', $authenticatorData->getAuthData() . $clientDataJSONHash, true)
        ) || throw new InvalidArgumentException('Invalid attestation object. Invalid nonce');
        array_key_exists('ctsProfileMatch', $payload) || throw new InvalidArgumentException(
            'Invalid attestation object. "ctsProfileMatch" is missing.'
        );
        $payload['ctsProfileMatch'] || throw new InvalidArgumentException(
            'Invalid attestation object. "ctsProfileMatch" value is false.'
        );
        array_key_exists('timestampMs', $payload) || throw new InvalidArgumentException(
            'Invalid attestation object. Timestamp is missing.'
        );
        is_int($payload['timestampMs']) || throw new InvalidArgumentException(
            'Invalid attestation object. Timestamp shall be an integer.'
        );
        $currentTime = time() * 1000;
        $payload['timestampMs'] <= $currentTime + $this->leeway || throw new InvalidArgumentException(sprintf(
            'Invalid attestation object. Issued in the future. Current time: %d. Response time: %d',
            $currentTime,
            $payload['timestampMs']
        ));
        $currentTime - $payload['timestampMs'] <= $this->maxAge || throw new InvalidArgumentException(sprintf(
            'Invalid attestation object. Too old. Current time: %d. Response time: %d',
            $currentTime,
            $payload['timestampMs']
        ));
    }

    private function validateSignature(JWS $jws, CertificateTrustPath $trustPath): void
    {
        $jwk = JWKFactory::createFromCertificate($trustPath->getCertificates()[0]);
        $isValid = $this->jwsVerifier?->verifyWithKey($jws, $jwk, 0);
        $isValid === true || throw new InvalidArgumentException('Invalid response signature');
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
            ->write($requestBody);

        $response = $this->client->sendRequest($request);
        $this->checkGoogleApiResponse($response);
        $responseBody = $this->getResponseBody($response);
        $responseBodyJson = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
        array_key_exists('isValidSignature', $responseBodyJson) || throw new InvalidArgumentException(
            'Invalid response.'
        );
        $responseBodyJson['isValidSignature'] === true || throw new InvalidArgumentException('Invalid response.');
    }

    private function getResponseBody(ResponseInterface $response): string
    {
        $responseBody = '';
        $response->getBody()
            ->rewind();
        do {
            $tmp = $response->getBody()
                ->read(1024);
            if ($tmp === '') {
                break;
            }
            $responseBody .= $tmp;
        } while (true);

        return $responseBody;
    }

    private function checkGoogleApiResponse(ResponseInterface $response): void
    {
        $response->getStatusCode() === 200 || throw new InvalidArgumentException('Request did not succeeded');
        $response->hasHeader('content-type') || throw new InvalidArgumentException('Unrecognized response');

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
