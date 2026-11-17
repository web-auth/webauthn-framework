<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\Extension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;

/**
 * Packed attestation statements whose attestation certificate is generated for the test, so that it carries the
 * extensions the test chooses. The keys are P-256 keys and the signatures ES256 ones.
 */
trait PackedAttestationTrait
{
    private function generateKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        return $key;
    }

    /**
     * Returns the DER encoding of a self-signed certificate that meets the requirements of the packed format for an
     * attestation certificate, with the given extensions after the Basic Constraints one.
     */
    private function attestationCertificate(OpenSSLAsymmetricKey $key, Extension ...$extensions): string
    {
        static::assertTrue(openssl_pkey_export($key, $pem));
        static::assertIsString($pem);
        $privateKeyInfo = PrivateKeyInfo::fromPEM(PEM::fromString($pem));
        static::assertInstanceOf(PrivateKeyInfo::class, $privateKeyInfo);
        $name = Name::fromString('CN=Enterprise Attestation Test,OU=Authenticator Attestation,O=Web Auth,C=FR');

        return TBSCertificate::create(
            $name,
            $privateKeyInfo->publicKeyInfo(),
            $name,
            Validity::fromStrings('2026-01-01 00:00:00', '2036-01-01 00:00:00', 'UTC')
        )
            ->withVersion(TBSCertificate::VERSION_3)
            ->withRandomSerialNumber(16)
            ->withAdditionalExtensions(BasicConstraintsExtension::create(true, false), ...$extensions)
            ->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $privateKeyInfo)
            ->toDER();
    }

    private function signWith(OpenSSLAsymmetricKey $key, string $data): string
    {
        static::assertTrue(openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256));
        static::assertIsString($signature);

        return $signature;
    }
}
