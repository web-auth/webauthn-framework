<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Attestation;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const OPENSSL_KEYTYPE_EC;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;
use const STR_PAD_LEFT;
use function strlen;

/**
 * A software authenticator holding a P-256 key pair. It answers creation options for the RP ID `localhost` with a new
 * credential and a `none` attestation.
 *
 * The authenticator data carries the user present, user verified and attested credential data flags (`0x45`), a zero
 * signature counter, a zero AAGUID and the public key as a COSE EC2 key for ES256.
 */
final readonly class SoftwarePasskey
{
    private const RP_ID = 'localhost';

    private const ORIGIN = 'https://localhost';

    public string $credentialId;

    private string $x;

    private string $y;

    public function __construct()
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $privateKey !== false || throw new RuntimeException('Unable to create the key pair.');
        $details = openssl_pkey_get_details($privateKey);
        $details !== false || throw new RuntimeException('Unable to read the key pair.');

        $this->credentialId = random_bytes(32);
        $this->x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $this->y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
    }

    public function attestation(string $challenge): string
    {
        $credentialPublicKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($this->x))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($this->y));
        $authenticatorData = hash('sha256', self::RP_ID, true)
            . chr(0x45)
            . pack('N', 0)
            . str_repeat("\0", 16)
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $credentialPublicKey;
        $attestationObject = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authenticatorData));
        $clientDataJSON = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $challenge,
            'origin' => self::ORIGIN,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return json_encode([
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJSON),
                'attestationObject' => Base64UrlSafe::encodeUnpadded((string) $attestationObject),
            ],
        ], JSON_THROW_ON_ERROR);
    }
}
