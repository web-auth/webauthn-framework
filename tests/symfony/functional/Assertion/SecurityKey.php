<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\Assertion;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;
use const STR_PAD_LEFT;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * A roaming security key holding one ES256 credential for one RP ID.
 *
 * Whoever holds the key gets assertions carrying the user presence flag (UP, 0x01). The user verification flag (UV,
 * 0x04) is only set once the PIN of the key has been entered, which `getAssertion()` models with `$userVerified`.
 *
 * @internal
 */
final readonly class SecurityKey
{
    private const FLAGS_USER_PRESENT = "\x01";

    private const FLAGS_USER_PRESENT_AND_VERIFIED = "\x05";

    private OpenSSLAsymmetricKey $privateKey;

    private string $credentialId;

    public function __construct(
        private string $rpId
    ) {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $privateKey instanceof OpenSSLAsymmetricKey || throw new RuntimeException('Unable to create the key pair.');
        $this->privateKey = $privateKey;
        $this->credentialId = random_bytes(32);
    }

    /**
     * The credential record the Relying Party stored when this key was registered to the user `$userHandle`.
     *
     * Its public key is the COSE map {1 (kty): 2 (EC2), 3 (alg): -7 (ES256), -1 (crv): 1 (P-256), -2 (x), -3 (y)},
     * with both coordinates left-padded to 32 bytes.
     */
    public function credentialRecordFor(string $userHandle): PublicKeyCredentialSource
    {
        $details = openssl_pkey_get_details($this->privateKey);
        $details !== false || throw new RuntimeException('Unable to read the public key.');
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01"
            . "\x21\x58\x20" . str_pad((string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT)
            . "\x22\x58\x20" . str_pad((string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        return new PublicKeyCredentialSource(
            $this->credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            EmptyTrustPath::create(),
            Uuid::fromBinary(str_repeat("\0", 16)),
            $coseKey,
            $userHandle,
            0
        );
    }

    /**
     * The PublicKeyCredential JSON that `navigator.credentials.get()` returns to a page on `$origin` for the base64url
     * `$challenge`. The signature counter stays at 0.
     */
    public function getAssertion(string $challenge, string $origin, bool $userVerified): string
    {
        $clientDataJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $challenge,
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authenticatorData = hash('sha256', $this->rpId, true)
            . ($userVerified ? self::FLAGS_USER_PRESENT_AND_VERIFIED : self::FLAGS_USER_PRESENT)
            . pack('N', 0);
        $signature = '';
        openssl_sign(
            $authenticatorData . hash('sha256', $clientDataJson, true),
            $signature,
            $this->privateKey,
            OPENSSL_ALGO_SHA256
        ) || throw new RuntimeException('Unable to sign the assertion.');

        return json_encode([
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJson),
                'authenticatorData' => Base64UrlSafe::encodeUnpadded($authenticatorData),
                'signature' => Base64UrlSafe::encodeUnpadded($signature),
                'userHandle' => null,
            ],
        ], JSON_THROW_ON_ERROR);
    }
}
