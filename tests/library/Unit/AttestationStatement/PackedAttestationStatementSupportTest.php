<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AttestationStatement;

use Cose\Algorithm\Manager;
use Cose\Algorithms;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\Tests\PackedAttestationTrait;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * Issue #1004: an enterprise attestation gives the serial number of the authenticator in the extension
 * id-fido-gen-ce-sernum (1.3.6.1.4.1.45724.1.1.2) of the attestation certificate.
 *
 * @internal
 */
final class PackedAttestationStatementSupportTest extends TestCase
{
    use PackedAttestationTrait;

    private const OID_FIDO_GEN_CE_SERNUM = '1.3.6.1.4.1.45724.1.1.2';

    private const SERIAL_NUMBER = "\x5d\x2b\x8f\x61\xa3\xc4\xe9\x07";

    private const DEPRECATION = 'Since web-auth/webauthn-lib 5.4.0: Verifying a packed attestation whose certificate carries the serial number extension (1.3.6.1.4.1.45724.1.1.2) marked critical or with a value that is not an OCTET STRING is deprecated and "Webauthn\AttestationStatement\PackedAttestationStatementSupport" will refuse it in 6.0.0. Until then, the extension is ignored.';

    #[Test]
    public function theSerialNumberOfAnEnterpriseAttestationIsRead(): void
    {
        [$trustPath, $deprecations] = $this->verify(
            UnknownExtension::create(self::OID_FIDO_GEN_CE_SERNUM, false, OctetString::create(self::SERIAL_NUMBER))
        );

        static::assertSame([], $deprecations);
        static::assertSame(self::SERIAL_NUMBER, $trustPath->authenticatorSerialNumber());
    }

    /**
     * @return iterable<string, array{Extension}>
     */
    public static function malformedSerialNumberExtensions(): iterable
    {
        yield 'marked critical' => [
            UnknownExtension::create(self::OID_FIDO_GEN_CE_SERNUM, true, OctetString::create(self::SERIAL_NUMBER)),
        ];
        yield 'an INTEGER' => [
            UnknownExtension::create(self::OID_FIDO_GEN_CE_SERNUM, false, Integer::create(19_600_953)),
        ];
        yield 'truncated' => [UnknownExtension::fromRawString(self::OID_FIDO_GEN_CE_SERNUM, false, "\xff")];
        yield 'empty' => [UnknownExtension::fromRawString(self::OID_FIDO_GEN_CE_SERNUM, false, '')];
        yield 'of a universal type pki-framework does not implement' => [
            UnknownExtension::fromRawString(self::OID_FIDO_GEN_CE_SERNUM, false, "\x0f\x00"),
        ];
    }

    #[Test]
    #[DataProvider('malformedSerialNumberExtensions')]
    public function aMalformedSerialNumberExtensionIsIgnoredWithADeprecation(Extension $extension): void
    {
        [$trustPath, $deprecations] = $this->verify($extension);

        static::assertSame([self::DEPRECATION], $deprecations);
        static::assertNull($trustPath->authenticatorSerialNumber());
    }

    #[Test]
    public function anAttestationCertificateWithoutSerialNumberExtensionHasNoSerialNumber(): void
    {
        [$trustPath, $deprecations] = $this->verify();

        static::assertSame([], $deprecations);
        static::assertNull($trustPath->authenticatorSerialNumber());
    }

    #[Test]
    public function theSerialNumberIsReadFromTheAttestationCertificateOnly(): void
    {
        $trustPath = CertificateTrustPath::create(CertificateToolbox::convertAllDERToPEM([
            $this->attestationCertificate($this->generateKey()),
            $this->attestationCertificate(
                $this->generateKey(),
                UnknownExtension::create(self::OID_FIDO_GEN_CE_SERNUM, false, OctetString::create(self::SERIAL_NUMBER))
            ),
        ]));

        static::assertNull($trustPath->authenticatorSerialNumber());
    }

    #[Test]
    public function aTrustPathWithoutCertificateHasNoSerialNumber(): void
    {
        static::assertNull(CertificateTrustPath::create([])->authenticatorSerialNumber());
    }

    /**
     * Loads and verifies a packed attestation statement whose attestation certificate carries the given extensions,
     * and returns its trust path with the deprecation messages triggered by the verification.
     *
     * @return array{CertificateTrustPath, list<string>}
     */
    private function verify(Extension ...$extensions): array
    {
        $support = PackedAttestationStatementSupport::create(Manager::create());
        $attestationKey = $this->generateKey();
        $rpIdHash = hash('sha256', 'localhost', true);
        $authData = $rpIdHash . "\x41\x00\x00\x00\x00";
        $clientDataJSONHash = hash('sha256', '{"type":"webauthn.create"}', true);
        $attestationStatement = $support->load([
            'fmt' => 'packed',
            'attStmt' => [
                'alg' => Algorithms::COSE_ALGORITHM_ES256,
                'sig' => $this->signWith($attestationKey, $authData . $clientDataJSONHash),
                'x5c' => [$this->attestationCertificate($attestationKey, ...$extensions)],
            ],
        ]);
        $authenticatorData = AuthenticatorData::create(
            $authData,
            $rpIdHash,
            "\x41",
            0,
            AttestedCredentialData::create(Uuid::v4(), 'credential-id')
        );

        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);
        try {
            $isValid = $support->isValid($clientDataJSONHash, $attestationStatement, $authenticatorData);
        } finally {
            restore_error_handler();
        }

        static::assertTrue($isValid);
        $trustPath = $attestationStatement->trustPath;
        static::assertInstanceOf(CertificateTrustPath::class, $trustPath);

        return [$trustPath, $deprecations];
    }
}
