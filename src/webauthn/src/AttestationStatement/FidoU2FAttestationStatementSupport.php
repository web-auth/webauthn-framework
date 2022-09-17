<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use Assert\Assertion;
use CBOR\Decoder;
use CBOR\MapObject;
use Cose\Key\Ec2Key;
use InvalidArgumentException;
use const OPENSSL_ALGO_SHA256;
use function openssl_pkey_get_public;
use function openssl_verify;
use Throwable;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\StringStream;
use Webauthn\TrustPath\CertificateTrustPath;

final class FidoU2FAttestationStatementSupport implements AttestationStatementSupport
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
        return 'fido-u2f';
    }

    /**
     * @param array<string, mixed> $attestation
     */
    public function load(array $attestation): AttestationStatement
    {
        array_key_exists('attStmt', $attestation) || throw new InvalidArgumentException('Invalid attestation object');
        foreach (['sig', 'x5c'] as $key) {
            array_key_exists($key, $attestation['attStmt']) || throw new InvalidArgumentException(sprintf(
                'The attestation statement value "%s" is missing.',
                $key
            ));
        }
        $certificates = $attestation['attStmt']['x5c'];
        Assertion::isArray($certificates, 'The attestation statement value "x5c" must be a list with one certificate.');
        Assertion::count(
            $certificates,
            1,
            'The attestation statement value "x5c" must be a list with one certificate.'
        );
        Assertion::allString(
            $certificates,
            'The attestation statement value "x5c" must be a list with one certificate.'
        );

        reset($certificates);
        $certificates = CertificateToolbox::convertAllDERToPEM($certificates);
        $this->checkCertificate($certificates[0]);

        return AttestationStatement::createBasic(
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
        Assertion::eq(
            $authenticatorData->getAttestedCredentialData()
                ?->getAaguid()
                ->__toString(),
            '00000000-0000-0000-0000-000000000000',
            'Invalid AAGUID for fido-u2f attestation statement. Shall be "00000000-0000-0000-0000-000000000000"'
        );
        $trustPath = $attestationStatement->getTrustPath();
        Assertion::isInstanceOf($trustPath, CertificateTrustPath::class, 'Invalid trust path');
        $dataToVerify = "\0";
        $dataToVerify .= $authenticatorData->getRpIdHash();
        $dataToVerify .= $clientDataJSONHash;
        $dataToVerify .= $authenticatorData->getAttestedCredentialData()
            ?->getCredentialId();
        $dataToVerify .= $this->extractPublicKey(
            $authenticatorData->getAttestedCredentialData()
                ?->getCredentialPublicKey()
        );

        return openssl_verify(
            $dataToVerify,
            $attestationStatement->get('sig'),
            $trustPath->getCertificates()[0],
            OPENSSL_ALGO_SHA256
        ) === 1;
    }

    private function extractPublicKey(?string $publicKey): string
    {
        Assertion::notNull($publicKey, 'The attested credential data does not contain a valid public key.');

        $publicKeyStream = new StringStream($publicKey);
        $coseKey = $this->decoder->decode($publicKeyStream);
        Assertion::true($publicKeyStream->isEOF(), 'Invalid public key. Presence of extra bytes.');
        $publicKeyStream->close();
        Assertion::isInstanceOf(
            $coseKey,
            MapObject::class,
            'The attested credential data does not contain a valid public key.'
        );

        $coseKey = $coseKey->normalize();
        $ec2Key = new Ec2Key($coseKey + [
            Ec2Key::TYPE => 2,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
        ]);

        return "\x04" . $ec2Key->x() . $ec2Key->y();
    }

    private function checkCertificate(string $publicKey): void
    {
        try {
            $resource = openssl_pkey_get_public($publicKey);
            $details = openssl_pkey_get_details($resource);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Invalid certificate or certificate chain', 0, $throwable);
        }
        Assertion::isArray($details, 'Invalid certificate or certificate chain');
        array_key_exists('ec', $details) || throw new InvalidArgumentException(
            'Invalid certificate or certificate chain'
        );
        array_key_exists('curve_name', $details['ec']) || throw new InvalidArgumentException(
            'Invalid certificate or certificate chain'
        );
        Assertion::eq($details['ec']['curve_name'], 'prime256v1', 'Invalid certificate or certificate chain');
        array_key_exists('curve_oid', $details['ec']) || throw new InvalidArgumentException(
            'Invalid certificate or certificate chain'
        );
        Assertion::eq($details['ec']['curve_oid'], '1.2.840.10045.3.1.7', 'Invalid certificate or certificate chain');
    }
}
