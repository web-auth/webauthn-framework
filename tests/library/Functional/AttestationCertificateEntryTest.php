<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use const PHP_EOL;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * The entries of "x5c" are DER certificates chosen by the client. They must reach the PEM parser and the OpenSSL
 * functions as DER, whatever their content: PEM text would let the client decide what each of them reads.
 *
 * @internal
 */
final class AttestationCertificateEntryTest extends AbstractTestCase
{
    private const YUBICO_AAGUID = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';

    /**
     * The entry holds two PEM blocks: a certificate the client issued to itself, with a space after its BEGIN line, then
     * the genuine attestation certificate of a Yubico security key, whose key the client does not have. The statement is
     * signed with the key of the first one. The certificate checks and the chain validation used to read the genuine
     * certificate while OpenSSL verified the signature with the key of the other one, so a software key was recorded
     * as a "basic" attestation of the Yubico model.
     */
    #[Test]
    public function aPackedStatementSignedWithAnotherKeyThanItsAttestationCertificateIsRejected(): void
    {
        [$selfIssuedCertificate, $selfIssuedKey] = SoftwareAuthenticator::selfSignedAttestationCertificate();
        $options = self::creationOptions();
        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                SoftwareAuthenticator::packed(
                    $options->challenge,
                    self::YUBICO_AAGUID,
                    [self::twoCertificates($selfIssuedCertificate)],
                    $selfIssuedKey
                ),
                PublicKeyCredential::class,
                'json'
            );

        $this->expectException(Throwable::class);

        $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $options, 'localhost');
    }

    /**
     * The same entry in a "fido-u2f" statement, which carries the null AAGUID. As soon as the certificate chain of such
     * a statement is validated, the genuine certificate would pass the chain validation while the signature is verified
     * with the key of the self-issued one.
     */
    #[Test]
    public function aFidoU2fStatementSignedWithAnotherKeyThanItsAttestationCertificateIsRejected(): void
    {
        [$selfIssuedCertificate, $selfIssuedKey] = SoftwareAuthenticator::selfSignedAttestationCertificate();
        $options = self::creationOptions();

        $this->expectException(Throwable::class);

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                SoftwareAuthenticator::fidoU2f(
                    $options->challenge,
                    [self::twoCertificates($selfIssuedCertificate)],
                    $selfIssuedKey
                ),
                PublicKeyCredential::class,
                'json'
            );
        $this->getAuthenticatorAttestationResponseValidator()
            ->check($publicKeyCredential->response, $options, 'localhost');
    }

    /**
     * PHP's OpenSSL functions open a key or certificate argument that starts with "file://" as a path. Such an entry
     * used to reach openssl_pkey_get_public() while the request body was deserialized, before any challenge or session
     * check: "/dev/ptmx" blocked the PHP worker for good. Here the path points to a valid certificate, which the
     * deserialization used to accept.
     */
    #[Test]
    public function aFidoU2fCertificateEntryIsNeverOpenedAsAPath(): void
    {
        [$certificate, $key] = SoftwareAuthenticator::selfSignedAttestationCertificate();
        $path = (string) tempnam(sys_get_temp_dir(), 'webauthn-x5c-');
        file_put_contents($path, self::toPem($certificate));

        $this->expectException(Throwable::class);
        $this->expectExceptionMessage('Invalid certificate or certificate chain');

        try {
            $this->getSerializer()
                ->deserialize(
                    SoftwareAuthenticator::fidoU2f(random_bytes(32), ['file:///-----BEGIN /..' . $path], $key),
                    PublicKeyCredential::class,
                    'json'
                );
        } finally {
            unlink($path);
        }
    }

    private static function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('My application', 'localhost'),
            PublicKeyCredentialUserEntity::create('mallory', random_bytes(32), 'Mallory'),
            random_bytes(32),
            [],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        );
    }

    /**
     * One x5c entry: the self-issued certificate as a PEM block with a space after its BEGIN line, which OpenSSL reads
     * and the PEM parser of pki-framework skips, then the genuine Yubico certificate as a regular PEM block.
     */
    private static function twoCertificates(string $selfIssuedCertificate): string
    {
        return str_replace(
            '-----BEGIN CERTIFICATE-----',
            '-----BEGIN CERTIFICATE----- ',
            self::toPem($selfIssuedCertificate)
        ) . file_get_contents(__DIR__ . '/../certificates/yubico-u2f-ee-serial-1955003842.crt');
    }

    private static function toPem(string $der): string
    {
        return '-----BEGIN CERTIFICATE-----' . PHP_EOL . chunk_split(
            base64_encode($der),
            64,
            PHP_EOL
        ) . '-----END CERTIFICATE-----' . PHP_EOL;
    }
}
