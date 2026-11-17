<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithms;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SpomkyLabs\Pki\ASN1\Type\Constructed\Sequence;
use SpomkyLabs\Pki\ASN1\Type\Primitive\OctetString;
use SpomkyLabs\Pki\ASN1\Type\Tagged\ExplicitlyTaggedType;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\Extension\UnknownExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use const STR_PAD_LEFT;
use function strlen;

/**
 * A software authenticator registering on https://localhost, for the tests that need attestation statements no real
 * authenticator produces: self-made attestation certificates, any AAGUID, arbitrary x5c entries.
 *
 * Each registration method returns the PublicKeyCredential JSON a browser would post. The client data only knows the
 * challenge. The authenticator data carries the UP and AT flags, a zero signature counter and a fresh ES256
 * credential key on P-256.
 */
final class SoftwareAuthenticator
{
    private const RP_ID = 'localhost';

    private const ORIGIN = 'https://localhost';

    private const NULL_AAGUID = '00000000-0000-0000-0000-000000000000';

    private const FLAGS_USER_PRESENT_AND_ATTESTED_CREDENTIAL_DATA = "\x41";

    private const ATTESTATION_CERTIFICATE_SUBJECT = 'c=XX,o=Software Authenticator,ou=Authenticator Attestation,cn=Self-made attestation certificate';

    private const APPLE_CREDENTIAL_CERTIFICATE_SUBJECT = 'cn=Self-made Apple credential certificate';

    private const APPLE_NONCE_EXTENSION = '1.2.840.113635.100.8.2';

    private const U2F_RESERVED_BYTE = "\x00";

    private const UNCOMPRESSED_POINT = "\x04";

    private const COORDINATE_LENGTH = 32;

    private const CREDENTIAL_ID_LENGTH_OFFSET = 53;

    /**
     * A "packed" full attestation. The statement is signed with $attestationKey, or with a fresh key when none is
     * given. Without $x5c, it carries a self-made attestation certificate for that key; with $x5c, the entries are
     * sent as they are.
     *
     * @param list<string>|null $x5c
     */
    public static function packed(
        string $challenge,
        string $aaguid,
        ?array $x5c = null,
        ?OpenSSLAsymmetricKey $attestationKey = null
    ): string {
        $clientDataJSON = self::clientDataJSON($challenge);
        $credentialId = random_bytes(16);
        $authData = self::authenticatorData($aaguid, $credentialId, self::newP256Key());
        $attestationKey ??= self::newP256Key();

        return self::publicKeyCredential($credentialId, $clientDataJSON, $authData, 'packed', [
            MapItem::create(
                TextStringObject::create('alg'),
                NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256)
            ),
            MapItem::create(
                TextStringObject::create('sig'),
                ByteStringObject::create(
                    self::sign($authData . hash('sha256', $clientDataJSON, true), $attestationKey)
                )
            ),
            MapItem::create(
                TextStringObject::create('x5c'),
                self::certificateList($x5c ?? [self::attestationCertificate($attestationKey)])
            ),
        ]);
    }

    /**
     * A "fido-u2f" attestation, always under the null AAGUID as the format requires. $x5c and $attestationKey follow
     * the rules of packed(); the format accepts exactly one certificate.
     *
     * @param list<string>|null $x5c
     */
    public static function fidoU2f(
        string $challenge,
        ?array $x5c = null,
        ?OpenSSLAsymmetricKey $attestationKey = null
    ): string {
        $clientDataJSON = self::clientDataJSON($challenge);
        $credentialId = random_bytes(16);
        $credentialKey = self::newP256Key();
        $authData = self::authenticatorData(self::NULL_AAGUID, $credentialId, $credentialKey);
        $attestationKey ??= self::newP256Key();
        [$x, $y] = self::coordinates($credentialKey);
        $signedData = self::U2F_RESERVED_BYTE
            . hash('sha256', self::RP_ID, true)
            . hash('sha256', $clientDataJSON, true)
            . $credentialId
            . self::UNCOMPRESSED_POINT . $x . $y;

        return self::publicKeyCredential($credentialId, $clientDataJSON, $authData, 'fido-u2f', [
            MapItem::create(
                TextStringObject::create('sig'),
                ByteStringObject::create(self::sign($signedData, $attestationKey))
            ),
            MapItem::create(
                TextStringObject::create('x5c'),
                self::certificateList($x5c ?? [self::attestationCertificate($attestationKey)])
            ),
        ]);
    }

    /**
     * An "apple" anonymous attestation. The format has no signature: the self-made credential certificate carries
     * SHA-256(authData || clientDataHash) in the extension 1.2.840.113635.100.8.2, as SEQUENCE { [1] OCTET STRING }.
     */
    public static function apple(string $challenge, string $aaguid): string
    {
        $clientDataJSON = self::clientDataJSON($challenge);
        $credentialId = random_bytes(16);
        $credentialKey = self::newP256Key();
        $authData = self::authenticatorData($aaguid, $credentialId, $credentialKey);
        $nonce = hash('sha256', $authData . hash('sha256', $clientDataJSON, true), true);
        $credentialCertificate = self::selfSignedCertificate(
            $credentialKey,
            self::APPLE_CREDENTIAL_CERTIFICATE_SUBJECT,
            UnknownExtension::create(
                self::APPLE_NONCE_EXTENSION,
                false,
                Sequence::create(ExplicitlyTaggedType::create(1, OctetString::create($nonce)))
            )
        );

        return self::publicKeyCredential($credentialId, $clientDataJSON, $authData, 'apple', [
            MapItem::create(TextStringObject::create('x5c'), self::certificateList([$credentialCertificate])),
        ]);
    }

    /**
     * A self-made attestation certificate (DER) and its private key. Its subject and its basic constraints (CA:FALSE)
     * are the ones the packed format asks for.
     *
     * @return array{0: string, 1: OpenSSLAsymmetricKey}
     */
    public static function selfSignedAttestationCertificate(): array
    {
        $attestationKey = self::newP256Key();

        return [self::attestationCertificate($attestationKey), $attestationKey];
    }

    /**
     * The COSE credential public key of a registration returned by this class, read from the authenticator data of
     * its attestation object.
     */
    public static function credentialPublicKey(string $publicKeyCredential): string
    {
        $credential = json_decode($publicKeyCredential, true, 512, JSON_THROW_ON_ERROR);
        $attestationObject = Decoder::create()
            ->decode(StringStream::create(Base64UrlSafe::decodeNoPadding($credential['response']['attestationObject'])))
            ->normalize();
        $authData = $attestationObject['authData'];
        $credentialIdLength = unpack('n', substr($authData, self::CREDENTIAL_ID_LENGTH_OFFSET, 2))[1];

        return substr($authData, self::CREDENTIAL_ID_LENGTH_OFFSET + 2 + $credentialIdLength);
    }

    private static function attestationCertificate(OpenSSLAsymmetricKey $attestationKey): string
    {
        return self::selfSignedCertificate(
            $attestationKey,
            self::ATTESTATION_CERTIFICATE_SUBJECT,
            BasicConstraintsExtension::create(true, false)
        );
    }

    private static function newP256Key(): OpenSSLAsymmetricKey
    {
        return openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
    }

    private static function sign(string $data, OpenSSLAsymmetricKey $key): string
    {
        $signature = '';
        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    /**
     * OpenSSL drops the leading zero bytes of a coordinate, COSE and U2F want exactly 32 bytes.
     *
     * @return array{0: string, 1: string}
     */
    private static function coordinates(OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        return [
            str_pad($details['ec']['x'], self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT),
            str_pad($details['ec']['y'], self::COORDINATE_LENGTH, "\0", STR_PAD_LEFT),
        ];
    }

    /**
     * @return string DER, issuer = subject, signed with the key of the subject
     */
    private static function selfSignedCertificate(
        OpenSSLAsymmetricKey $key,
        string $subject,
        Extension $extension
    ): string {
        $pem = '';
        openssl_pkey_export($key, $pem);
        $privateKey = PrivateKeyInfo::fromPEM(PEM::fromString($pem));
        $name = Name::fromString($subject);

        return TBSCertificate::create(
            $name,
            $privateKey->publicKeyInfo(),
            $name,
            Validity::fromStrings('-1 hour', '+1 day')
        )
            ->withAdditionalExtensions($extension)
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $privateKey)
            ->toDER();
    }

    /**
     * @param list<string> $certificates
     */
    private static function certificateList(array $certificates): ListObject
    {
        return ListObject::create(
            array_map(
                ByteStringObject::create(...),
                $certificates
            )
        );
    }

    private static function clientDataJSON(string $challenge): string
    {
        return json_encode([
            'type' => 'webauthn.create',
            'challenge' => Base64UrlSafe::encodeUnpadded($challenge),
            'origin' => self::ORIGIN,
        ], JSON_THROW_ON_ERROR);
    }

    private static function authenticatorData(
        string $aaguid,
        string $credentialId,
        OpenSSLAsymmetricKey $credentialKey
    ): string {
        [$x, $y] = self::coordinates($credentialKey);
        $credentialPublicKey = MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create(Key::TYPE_EC2)),
            MapItem::create(
                UnsignedIntegerObject::create(Key::ALG),
                NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256)
            ),
            MapItem::create(
                NegativeIntegerObject::create(Ec2Key::DATA_CURVE),
                UnsignedIntegerObject::create(Ec2Key::CURVE_P256)
            ),
            MapItem::create(NegativeIntegerObject::create(Ec2Key::DATA_X), ByteStringObject::create($x)),
            MapItem::create(NegativeIntegerObject::create(Ec2Key::DATA_Y), ByteStringObject::create($y)),
        ]);

        return hash('sha256', self::RP_ID, true)
            . self::FLAGS_USER_PRESENT_AND_ATTESTED_CREDENTIAL_DATA
            . pack('N', 0)
            . hex2bin(str_replace('-', '', $aaguid))
            . pack('n', strlen($credentialId)) . $credentialId
            . $credentialPublicKey;
    }

    /**
     * @param MapItem[] $attStmt
     */
    private static function publicKeyCredential(
        string $credentialId,
        string $clientDataJSON,
        string $authData,
        string $fmt,
        array $attStmt
    ): string {
        $attestationObject = MapObject::create([
            MapItem::create(TextStringObject::create('fmt'), TextStringObject::create($fmt)),
            MapItem::create(TextStringObject::create('attStmt'), MapObject::create($attStmt)),
            MapItem::create(TextStringObject::create('authData'), ByteStringObject::create($authData)),
        ]);

        return json_encode([
            'id' => Base64UrlSafe::encodeUnpadded($credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJSON),
                'attestationObject' => Base64UrlSafe::encodeUnpadded((string) $attestationObject),
            ],
        ], JSON_THROW_ON_ERROR);
    }
}
