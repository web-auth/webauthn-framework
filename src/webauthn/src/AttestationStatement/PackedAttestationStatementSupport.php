<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use CBOR\Decoder;
use CBOR\MapObject;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Algorithms;
use Cose\Key\Key;
use function count;
use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_string;
use function openssl_verify;
use RuntimeException;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\StringStream;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EcdaaKeyIdTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\Util\CoseSignatureFixer;

final class PackedAttestationStatementSupport implements AttestationStatementSupport
{
    private readonly Decoder $decoder;

    public function __construct(
        private readonly Manager $algorithmManager
    ) {
        $this->decoder = Decoder::create();
    }

    public static function create(Manager $algorithmManager): self
    {
        return new self($algorithmManager);
    }

    public function name(): string
    {
        return 'packed';
    }

    /**
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        array_key_exists('sig', $attestation['attStmt']) || throw new InvalidArgumentException(
            'The attestation statement value "sig" is missing.'
        );
        array_key_exists('alg', $attestation['attStmt']) || throw new InvalidArgumentException(
            'The attestation statement value "alg" is missing.'
        );
        is_string($attestation['attStmt']['sig']) || throw new InvalidArgumentException(
            'The attestation statement value "sig" is missing.'
        );

        return match (true) {
            array_key_exists('x5c', $attestation['attStmt']) => $this->loadBasicType($attestation),
            array_key_exists('ecdaaKeyId', $attestation['attStmt']) => $this->loadEcdaaType($attestation['attStmt']),
            default => $this->loadEmptyType($attestation),
        };
    }

    public function isValid(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        $trustPath = $attestationStatement->getTrustPath();

        return match (true) {
            $trustPath instanceof CertificateTrustPath => $this->processWithCertificate(
                $clientDataJSONHash,
                $attestationStatement,
                $authenticatorData,
                $trustPath
            ),
            $trustPath instanceof EcdaaKeyIdTrustPath => $this->processWithECDAA(),
            $trustPath instanceof EmptyTrustPath => $this->processWithSelfAttestation(
                $clientDataJSONHash,
                $attestationStatement,
                $authenticatorData
            ),
            default => throw new InvalidArgumentException('Unsupported attestation statement'),
        };
    }

    /**
     * @param mixed[] $attestation
     */
    private function loadBasicType(array $attestation): AttestationStatement
    {
        $certificates = $attestation['attStmt']['x5c'];
        is_array($certificates) || throw new InvalidArgumentException(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        count($certificates) > 0 || throw new InvalidArgumentException(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);

        return AttestationStatement::createBasic(
            $attestation['fmt'],
            $attestation['attStmt'],
            new CertificateTrustPath($certificates)
        );
    }

    /**
     * @param array<string, mixed> $attestation
     */
    private function loadEcdaaType(array $attestation): AttestationStatement
    {
        $ecdaaKeyId = $attestation['attStmt']['ecdaaKeyId'];
        is_string($ecdaaKeyId) || throw new InvalidArgumentException(
            'The attestation statement value "ecdaaKeyId" is invalid.'
        );

        return AttestationStatement::createEcdaa(
            $attestation['fmt'],
            $attestation['attStmt'],
            new EcdaaKeyIdTrustPath($attestation['ecdaaKeyId'])
        );
    }

    /**
     * @param mixed[] $attestation
     */
    private function loadEmptyType(array $attestation): AttestationStatement
    {
        return AttestationStatement::createSelf($attestation['fmt'], $attestation['attStmt'], new EmptyTrustPath());
    }

    private function checkCertificate(string $attestnCert, AuthenticatorData $authenticatorData): void
    {
        $parsed = openssl_x509_parse($attestnCert);
        is_array($parsed) || throw new InvalidArgumentException('Invalid certificate');

        //Check version
        isset($parsed['version']) || throw new InvalidArgumentException('Invalid certificate version');
        $parsed['version'] === 2 || throw new InvalidArgumentException('Invalid certificate version');

        //Check subject field
        isset($parsed['name']) || throw new InvalidArgumentException(
            'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"'
        );
        str_contains((string) $parsed['name'], '/OU=Authenticator Attestation') || throw new InvalidArgumentException(
            'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"'
        );

        //Check extensions
        isset($parsed['extensions']) || throw new InvalidArgumentException('Certificate extensions are missing');
        is_array($parsed['extensions']) || throw new InvalidArgumentException('Certificate extensions are missing');

        //Check certificate is not a CA cert
        isset($parsed['extensions']['basicConstraints']) || throw new InvalidArgumentException(
            'The Basic Constraints extension must have the CA component set to false'
        );
        $parsed['extensions']['basicConstraints'] === 'CA:FALSE' || throw new InvalidArgumentException(
            'The Basic Constraints extension must have the CA component set to false'
        );

        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        $attestedCredentialData !== null || throw new InvalidArgumentException('No attested credential available');

        // id-fido-gen-ce-aaguid OID check
        if (in_array('1.3.6.1.4.1.45724.1.1.4', $parsed['extensions'], true)) {
            hash_equals(
                $attestedCredentialData->getAaguid()
                    ->toBinary(),
                $parsed['extensions']['1.3.6.1.4.1.45724.1.1.4']
            ) || throw new InvalidArgumentException(
                'The value of the "aaguid" does not match with the certificate'
            );
        }
    }

    private function processWithCertificate(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData,
        CertificateTrustPath $trustPath
    ): bool {
        $certificates = $trustPath->getCertificates();

        // Check leaf certificate
        $this->checkCertificate($certificates[0], $authenticatorData);

        // Get the COSE algorithm identifier and the corresponding OpenSSL one
        $coseAlgorithmIdentifier = (int) $attestationStatement->get('alg');
        $opensslAlgorithmIdentifier = Algorithms::getOpensslAlgorithmFor($coseAlgorithmIdentifier);

        // Verification of the signature
        $signedData = $authenticatorData->getAuthData() . $clientDataJSONHash;
        $result = openssl_verify(
            $signedData,
            $attestationStatement->get('sig'),
            $certificates[0],
            $opensslAlgorithmIdentifier
        );

        return $result === 1;
    }

    private function processWithECDAA(): never
    {
        throw new RuntimeException('ECDAA not supported');
    }

    private function processWithSelfAttestation(
        string $clientDataJSONHash,
        AttestationStatement $attestationStatement,
        AuthenticatorData $authenticatorData
    ): bool {
        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        $attestedCredentialData !== null || throw new InvalidArgumentException('No attested credential available');
        $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
        $credentialPublicKey !== null || throw new InvalidArgumentException('No credential public key available');
        $publicKeyStream = new StringStream($credentialPublicKey);
        $publicKey = $this->decoder->decode($publicKeyStream);
        $publicKeyStream->isEOF() || throw new InvalidArgumentException(
            'Invalid public key. Presence of extra bytes.'
        );
        $publicKeyStream->close();
        $publicKey instanceof MapObject || throw new InvalidArgumentException(
            'The attested credential data does not contain a valid public key.'
        );
        $publicKey = $publicKey->normalize();
        $publicKey = new Key($publicKey);
        $publicKey->alg() === (int) $attestationStatement->get('alg') || throw new InvalidArgumentException(
            'The algorithm of the attestation statement and the key are not identical.'
        );

        $dataToVerify = $authenticatorData->getAuthData() . $clientDataJSONHash;
        $algorithm = $this->algorithmManager->get((int) $attestationStatement->get('alg'));
        if (! $algorithm instanceof Signature) {
            throw new RuntimeException('Invalid algorithm');
        }
        $signature = CoseSignatureFixer::fix($attestationStatement->get('sig'), $algorithm);

        return $algorithm->verify($dataToVerify, $publicKey, $signature);
    }
}
