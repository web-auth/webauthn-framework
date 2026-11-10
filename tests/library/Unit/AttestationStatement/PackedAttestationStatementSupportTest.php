<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CommonNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\CountryNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\OrganizationalUnitNameValue;
use SpomkyLabs\Pki\X501\ASN1\AttributeValue\OrganizationNameValue;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X501\ASN1\RDN;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use const STR_PAD_LEFT;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorData;
use Webauthn\Exception\AttestationStatementVerificationException;

/**
 * Issue #1005: Yubico documents the certificate of an enterprise attestation with the Subject
 * "CN=Yubico Fido EE (Serial=19600953),OU=Enterprise Attestation,O=Yubico AB,C=SE". Each test issues a certificate
 * with the Organization Unit it needs for a P-256 key generated on the fly, and signs the attestation with that key.
 *
 * @internal
 */
final class PackedAttestationStatementSupportTest extends TestCase
{
    private const AAGUID = '6a1d2b7e-4c3f-4e8a-9b5d-0f2c8e7a1b3d';

    private const OID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

    private const OID_FIDO_GEN_CE_SERNUM = '1.3.6.1.4.1.45724.1.1.2';

    private const SERIAL_NUMBER = 19600953;

    private OpenSSLAsymmetricKey $attestationKey;

    private string $authData;

    private string $clientDataJSONHash;

    protected function setUp(): void
    {
        $attestationKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $attestationKey);
        $this->attestationKey = $attestationKey;
        $this->clientDataJSONHash = hash('sha256', '{"type":"webauthn.create"}', true);
        $this->authData = hash('sha256', 'localhost', true) . chr(0x41) . pack('N', 0)
            . Uuid::fromString(self::AAGUID)->toBinary()
            . pack('n', 16) . str_repeat("\x01", 16)
            . $this->credentialPublicKey();
    }

    #[Test]
    public function theEnterpriseAttestationCertificateYubicoDocumentsIsAccepted(): void
    {
        $support = PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create()));
        $attestationStatement = $this->attestationStatement($support, 'Enterprise Attestation', true);

        static::assertTrue(
            $support->isValid($this->clientDataJSONHash, $attestationStatement, $this->authenticatorData())
        );
    }

    #[Test]
    public function theSignatureOfAnEnterpriseAttestationIsStillVerified(): void
    {
        $support = PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create()));
        $attestationStatement = $this->attestationStatement($support, 'Enterprise Attestation', true);

        static::assertFalse(
            $support->isValid(
                hash('sha256', '{"type":"webauthn.get"}', true),
                $attestationStatement,
                $this->authenticatorData()
            )
        );
    }

    #[Test]
    public function theEnterpriseAttestationUnitIsRejectedWithoutTheSerialNumberExtension(): void
    {
        $support = PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create()));
        $attestationStatement = $this->attestationStatement($support, 'Enterprise Attestation', false);

        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage(
            'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"'
        );

        $support->isValid($this->clientDataJSONHash, $attestationStatement, $this->authenticatorData());
    }

    #[Test]
    #[DataProvider('otherOrganizationUnits')]
    public function anyOtherUnitIsRejectedEvenWithTheSerialNumberExtension(string $organizationUnit): void
    {
        $support = PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create()));
        $attestationStatement = $this->attestationStatement($support, $organizationUnit, true);

        $this->expectException(AttestationStatementVerificationException::class);
        $this->expectExceptionMessage(
            'Invalid certificate name. The Subject Organization Unit must be "Authenticator Attestation"'
        );

        $support->isValid($this->clientDataJSONHash, $attestationStatement, $this->authenticatorData());
    }

    #[Test]
    #[DataProvider('serialNumberExtensionPresence')]
    public function theAuthenticatorAttestationUnitIsStillAccepted(bool $withSerialNumber): void
    {
        $support = PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create()));
        $attestationStatement = $this->attestationStatement($support, 'Authenticator Attestation', $withSerialNumber);

        static::assertTrue(
            $support->isValid($this->clientDataJSONHash, $attestationStatement, $this->authenticatorData())
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherOrganizationUnits(): iterable
    {
        yield 'lowercase' => ['enterprise attestation'];
        yield 'trailing space' => ['Enterprise Attestation '];
        yield 'another unit' => ['Enterprise'];
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function serialNumberExtensionPresence(): iterable
    {
        yield 'without the serial number extension' => [false];
        yield 'with the serial number extension' => [true];
    }

    private function attestationStatement(
        PackedAttestationStatementSupport $support,
        string $organizationUnit,
        bool $withSerialNumber
    ): AttestationStatement {
        openssl_pkey_export($this->attestationKey, $privateKey);
        $privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromString($privateKey));
        $extensions = [
            BasicConstraintsExtension::create(true, false),
            UnknownExtension::create(
                self::OID_FIDO_GEN_CE_AAGUID,
                false,
                OctetString::create(Uuid::fromString(self::AAGUID)->toBinary())
            ),
        ];
        if ($withSerialNumber) {
            $extensions[] = UnknownExtension::create(
                self::OID_FIDO_GEN_CE_SERNUM,
                false,
                OctetString::create(pack('N', self::SERIAL_NUMBER))
            );
        }
        $certificate = TBSCertificate::create(
            Name::create(
                RDN::fromAttributeValues(CountryNameValue::create('SE')),
                RDN::fromAttributeValues(OrganizationNameValue::create('Yubico AB')),
                RDN::fromAttributeValues(OrganizationalUnitNameValue::create($organizationUnit)),
                RDN::fromAttributeValues(CommonNameValue::create('Yubico Fido EE (Serial=' . self::SERIAL_NUMBER . ')'))
            ),
            $privateKeyInfo->publicKeyInfo(),
            Name::fromString('CN=Enterprise Attestation Test CA'),
            Validity::fromStrings('now', 'now + 1 day')
        )
            ->withAdditionalExtensions(...$extensions)
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $privateKeyInfo);
        openssl_sign(
            $this->authData . $this->clientDataJSONHash,
            $signature,
            $this->attestationKey,
            OPENSSL_ALGO_SHA256
        );

        return $support->load([
            'fmt' => 'packed',
            'attStmt' => [
                'alg' => -7,
                'sig' => $signature,
                'x5c' => [$certificate->toDER()],
            ],
        ]);
    }

    private function authenticatorData(): AuthenticatorData
    {
        return AuthenticatorData::create(
            $this->authData,
            hash('sha256', 'localhost', true),
            chr(0x41),
            0,
            AttestedCredentialData::create(
                Uuid::fromString(self::AAGUID),
                str_repeat("\x01", 16),
                $this->credentialPublicKey()
            )
        );
    }

    private function credentialPublicKey(): string
    {
        $details = openssl_pkey_get_details($this->attestationKey);
        static::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */

        return (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(
                NegativeIntegerObject::create(-2),
                ByteStringObject::create(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT))
            )
            ->add(
                NegativeIntegerObject::create(-3),
                ByteStringObject::create(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))
            );
    }
}
