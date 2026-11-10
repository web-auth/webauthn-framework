<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;
use const STR_PAD_LEFT;
use function strlen;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CollectedClientData;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * Packed attestations with an attestation certificate, signed when the test runs with the keys of
 * tests/library/certificates/enterprise-attestation. "organization" chains to the root CA of an organization, as the
 * enterprise attestation of the devices it manages does; "vendor" chains to the root CA of a maker, as a regular
 * attestation does.
 */
final class PackedAttestationFixture
{
    public const ORGANIZATION = 'organization';

    public const VENDOR = 'vendor';

    public const MANAGED_DEVICE_AAGUID = 'dd4ec289-e01d-41c9-bb89-70fa845d4bf2';

    public const VENDOR_AAGUID = '6a8d4d1e-3b52-4a5e-9f63-0f2b8e2d7c41';

    private const DIRECTORY = __DIR__ . '/../library/certificates/enterprise-attestation/';

    public static function rootCertificate(string $issuer): string
    {
        return self::read($issuer . '-root-ca.pem');
    }

    public static function attestationCertificate(string $issuer): string
    {
        return self::read($issuer . '-attestation.pem');
    }

    public static function attestationStatementSupportManager(): AttestationStatementSupportManager
    {
        return AttestationStatementSupportManager::create([
            PackedAttestationStatementSupport::create(Manager::create()->add(ES256::create())),
        ]);
    }

    public static function credential(
        string $issuer,
        string $aaguid,
        string $challenge,
        string $rpId = 'localhost'
    ): PublicKeyCredential {
        $credentialId = random_bytes(16);
        $authData = hash('sha256', $rpId, true)
            . chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV | AuthenticatorData::FLAG_AT)
            . pack('N', 0)
            . Uuid::fromString($aaguid)->toBinary()
            . pack('n', strlen($credentialId))
            . $credentialId
            . self::credentialPublicKey();
        $clientDataJSON = json_encode([
            'type' => 'webauthn.create',
            'challenge' => Base64UrlSafe::encodeUnpadded($challenge),
            'origin' => 'https://' . $rpId,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR);
        openssl_sign(
            $authData . hash('sha256', $clientDataJSON, true),
            $signature,
            self::read($issuer . '-attestation-key.pem'),
            OPENSSL_ALGO_SHA256
        ) || throw new RuntimeException('Unable to sign the attestation statement.');
        $attestationObject = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('packed'))
            ->add(
                TextStringObject::create('attStmt'),
                MapObject::create()
                    ->add(TextStringObject::create('alg'), NegativeIntegerObject::create(-7))
                    ->add(TextStringObject::create('sig'), ByteStringObject::create($signature))
                    ->add(
                        TextStringObject::create('x5c'),
                        ListObject::create()
                            ->add(ByteStringObject::create(self::der(self::attestationCertificate($issuer))))
                    )
            )
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return PublicKeyCredential::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $credentialId,
            AuthenticatorAttestationResponse::create(
                CollectedClientData::create(
                    $clientDataJSON,
                    json_decode($clientDataJSON, true, flags: JSON_THROW_ON_ERROR)
                ),
                AttestationObjectLoader::create(self::attestationStatementSupportManager())->load(
                    Base64UrlSafe::encodeUnpadded((string) $attestationObject)
                )
            )
        );
    }

    public static function der(string $pem): string
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $pem) ?? '', true);
        $der !== false || throw new RuntimeException('Invalid PEM certificate.');

        return $der;
    }

    private static function credentialPublicKey(): string
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $privateKey instanceof OpenSSLAsymmetricKey || throw new RuntimeException('Unable to create a key.');
        /** @var array{ec: array{x: string, y: string}} $details */
        $details = openssl_pkey_get_details($privateKey);

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

    private static function read(string $file): string
    {
        $content = file_get_contents(self::DIRECTORY . $file);
        $content !== false || throw new RuntimeException('Unable to read ' . $file);

        return $content;
    }
}
