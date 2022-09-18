<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use CBOR\Decoder;
use CBOR\Normalizable;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use function count;
use InvalidArgumentException;
use function is_array;
use function openssl_pkey_get_public;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\StringStream;
use Webauthn\TrustPath\CertificateTrustPath;

final class AppleAttestationStatementSupport implements AttestationStatementSupport
{
    private readonly Decoder $decoder;

    public function __construct()
    {
        $this->decoder = Decoder::create();
    }

    public static function create(): self
    {
        return new self();
    }

    public function name(): string
    {
        return 'apple';
    }

    /**
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        array_key_exists('attStmt', $attestation) || throw new InvalidArgumentException('Invalid attestation object');
        array_key_exists('x5c', $attestation['attStmt']) || throw new InvalidArgumentException(
            'The attestation statement value "x5c" is missing.'
        );
        $certificates = $attestation['attStmt']['x5c'];
        (is_countable($certificates) ? count($certificates) : 0) > 0 || throw new InvalidArgumentException(
            'The attestation statement value "x5c" must be a list with at least one certificate.'
        );
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);

        return AttestationStatement::createAnonymizationCA(
            $attestation['fmt'],
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

        //Decode leaf attestation certificate
        $leaf = $certificates[0];

        $this->checkCertificateAndGetPublicKey($leaf, $clientDataJSONHash, $authenticatorData);

        return true;
    }

    private function checkCertificateAndGetPublicKey(
        string $certificate,
        string $clientDataHash,
        AuthenticatorData $authenticatorData
    ): void {
        $resource = openssl_pkey_get_public($certificate);
        $details = openssl_pkey_get_details($resource);
        is_array($details) || throw new InvalidArgumentException('Unable to read the certificate');

        //Check that authData publicKey matches the public key in the attestation certificate
        $attestedCredentialData = $authenticatorData->getAttestedCredentialData();
        $attestedCredentialData !== null || throw new InvalidArgumentException('No attested credential data found');
        $publicKeyData = $attestedCredentialData->getCredentialPublicKey();
        $publicKeyData !== null || throw new InvalidArgumentException('No attested public key found');
        $publicDataStream = new StringStream($publicKeyData);
        $coseKey = $this->decoder->decode($publicDataStream);
        $coseKey instanceof Normalizable || throw new InvalidArgumentException('Invalid attested public key found');
        $publicDataStream->isEOF() || throw new InvalidArgumentException(
            'Invalid public key data. Presence of extra bytes.'
        );
        $publicDataStream->close();
        $publicKey = Key::createFromData($coseKey->normalize());

        ($publicKey instanceof Ec2Key) || ($publicKey instanceof RsaKey) || throw new InvalidArgumentException(
            'Unsupported key type'
        );

        //We check the attested key corresponds to the key in the certificate
        $publicKey->asPEM() === $details['key'] || throw new InvalidArgumentException('Invalid key');

        /*---------------------------*/
        $certDetails = openssl_x509_parse($certificate);

        //Find Apple Extension with OID "1.2.840.113635.100.8.2" in certificate extensions
        is_array($certDetails) || throw new InvalidArgumentException('The certificate is not valid');
        array_key_exists('extensions', $certDetails) || throw new InvalidArgumentException(
            'The certificate has no extension'
        );
        is_array($certDetails['extensions']) || throw new InvalidArgumentException('The certificate has no extension');
        array_key_exists('1.2.840.113635.100.8.2', $certDetails['extensions']) || throw new InvalidArgumentException(
            'The certificate extension "1.2.840.113635.100.8.2" is missing'
        );
        $extension = $certDetails['extensions']['1.2.840.113635.100.8.2'];

        $nonceToHash = $authenticatorData->getAuthData() . $clientDataHash;
        $nonce = hash('sha256', $nonceToHash);

        //'3024a1220420' corresponds to the Sequence+Explicitly Tagged Object + Octet Object
        '3024a1220420' . $nonce === bin2hex((string) $extension) || throw new InvalidArgumentException(
            'The client data hash is not valid'
        );
    }
}
