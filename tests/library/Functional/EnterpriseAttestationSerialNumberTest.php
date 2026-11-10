<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Algorithm\Manager;
use Cose\Algorithms;
use const E_USER_DEPRECATED;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use const STR_PAD_LEFT;
use function strlen;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CheckAttestationFormatIsKnownAndValid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\Tests\PackedAttestationTrait;
use Webauthn\TrustPath\CertificateTrustPath;

/**
 * Issue #1004: the serial number of an enterprise attestation reaches the relying party through the trust path of the
 * credential record. The ceremony is reduced to the verification of the attestation statement, which keeps the
 * metadata of the authenticator out of the test.
 *
 * @internal
 */
final class EnterpriseAttestationSerialNumberTest extends AbstractTestCase
{
    use PackedAttestationTrait;

    private const AAGUID = 'b3a1f6d2-5c1e-4f0b-9e7d-2a4c8e6f1d03';

    private const SERIAL_NUMBER = "\x5d\x2b\x8f\x61\xa3\xc4\xe9\x07";

    #[Test]
    public function theCredentialRecordOfAnEnterpriseAttestationGivesTheSerialNumberOfTheAuthenticator(): void
    {
        $options = $this->creationOptions(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE
        );

        $credentialRecord = $this->register($options);

        static::assertInstanceOf(CertificateTrustPath::class, $credentialRecord->trustPath);
        static::assertSame(self::SERIAL_NUMBER, $credentialRecord->trustPath->authenticatorSerialNumber());
        $storedCredentialRecord = $this->getSerializer()
            ->deserialize(
                $this->getSerializer()
                    ->serialize($credentialRecord, 'json'),
                CredentialRecord::class,
                'json'
            );
        static::assertInstanceOf(CredentialRecord::class, $storedCredentialRecord);
        static::assertInstanceOf(CertificateTrustPath::class, $storedCredentialRecord->trustPath);
        static::assertSame(self::SERIAL_NUMBER, $storedCredentialRecord->trustPath->authenticatorSerialNumber());
    }

    #[Test]
    public function aSerialNumberReceivedWithoutAskingForAnEnterpriseAttestationIsNotRefused(): void
    {
        $options = $this->creationOptions(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT);

        $credentialRecord = $this->register($options);

        static::assertInstanceOf(CertificateTrustPath::class, $credentialRecord->trustPath);
        static::assertSame(self::SERIAL_NUMBER, $credentialRecord->trustPath->authenticatorSerialNumber());
    }

    private function creationOptions(string $attestation): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'localhost'),
            PublicKeyCredentialUserEntity::create('john.doe', 'user-handle', 'John Doe'),
            random_bytes(32),
            attestation: $attestation
        );
    }

    /**
     * Runs the registration of a credential whose packed attestation certificate carries the AAGUID of the
     * authenticator and its serial number, and checks that it triggers no deprecation.
     */
    private function register(PublicKeyCredentialCreationOptions $options): CredentialRecord
    {
        $validator = AuthenticatorAttestationResponseValidator::create(
            new CeremonyStepManager([
                new CheckAttestationFormatIsKnownAndValid(
                    AttestationStatementSupportManager::create([
                        PackedAttestationStatementSupport::create(Manager::create()),
                    ])
                ),
            ])
        );
        $response = $this->attestationResponse($options);

        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);
        try {
            $credentialRecord = $validator->check($response, $options, 'localhost');
        } finally {
            restore_error_handler();
        }

        static::assertSame([], $deprecations);

        return $credentialRecord;
    }

    private function attestationResponse(PublicKeyCredentialCreationOptions $options): AuthenticatorAttestationResponse
    {
        $credentialId = random_bytes(32);
        $credentialKey = openssl_pkey_get_details($this->generateKey());
        static::assertIsArray($credentialKey);
        /** @var array{ec: array{x: string, y: string}} $credentialKey */
        $credentialPublicKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(
                NegativeIntegerObject::create(-2),
                ByteStringObject::create(str_pad($credentialKey['ec']['x'], 32, "\0", STR_PAD_LEFT))
            )
            ->add(
                NegativeIntegerObject::create(-3),
                ByteStringObject::create(str_pad($credentialKey['ec']['y'], 32, "\0", STR_PAD_LEFT))
            );
        $authData = hash('sha256', 'localhost', true)
            . chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_AT)
            . pack('N', 0)
            . Uuid::fromString(self::AAGUID)->toBinary()
            . pack('n', strlen($credentialId))
            . $credentialId
            . $credentialPublicKey;
        $clientDataJSON = json_encode([
            'type' => 'webauthn.create',
            'challenge' => Base64UrlSafe::encodeUnpadded($options->challenge),
            'origin' => 'https://localhost',
        ], JSON_THROW_ON_ERROR);

        $attestationKey = $this->generateKey();
        $attestationCertificate = $this->attestationCertificate(
            $attestationKey,
            UnknownExtension::create(
                '1.3.6.1.4.1.45724.1.1.4',
                false,
                OctetString::create(Uuid::fromString(self::AAGUID)->toBinary())
            ),
            UnknownExtension::create('1.3.6.1.4.1.45724.1.1.2', false, OctetString::create(self::SERIAL_NUMBER))
        );
        $attestationObject = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('packed'))
            ->add(
                TextStringObject::create('attStmt'),
                MapObject::create()
                    ->add(
                        TextStringObject::create('alg'),
                        NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256)
                    )
                    ->add(
                        TextStringObject::create('sig'),
                        ByteStringObject::create(
                            $this->signWith($attestationKey, $authData . hash('sha256', $clientDataJSON, true))
                        )
                    )
                    ->add(
                        TextStringObject::create('x5c'),
                        ListObject::create()->add(ByteStringObject::create($attestationCertificate))
                    )
            )
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                json_encode([
                    'id' => Base64UrlSafe::encodeUnpadded($credentialId),
                    'rawId' => Base64UrlSafe::encodeUnpadded($credentialId),
                    'type' => 'public-key',
                    'response' => [
                        'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJSON),
                        'attestationObject' => Base64UrlSafe::encodeUnpadded((string) $attestationObject),
                    ],
                ], JSON_THROW_ON_ERROR),
                PublicKeyCredential::class,
                'json'
            );
        static::assertInstanceOf(PublicKeyCredential::class, $publicKeyCredential);
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $publicKeyCredential->response);

        return $publicKeyCredential->response;
    }
}
