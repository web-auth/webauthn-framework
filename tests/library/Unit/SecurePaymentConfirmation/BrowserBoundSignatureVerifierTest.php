<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use function ord;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignatureVerifier;

/**
 * @internal
 */
final class BrowserBoundSignatureVerifierTest extends TestCase
{
    #[Test]
    public function happyPathRoundTripWithFreshECDSAKey(): void
    {
        $clientDataJSON = '{"type":"payment.get","challenge":"abc","origin":"http://localhost"}';

        // 1. Generate a fresh P-256 keypair (the browser-bound key the
        //    user agent would have created at registration time).
        $keypair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertNotFalse($keypair);
        $details = openssl_pkey_get_details($keypair);
        static::assertIsArray($details);

        // 2. Sign the clientDataJSON with the private half.
        openssl_sign($clientDataJSON, $derSignature, $keypair, OPENSSL_ALGO_SHA256);
        $rawSignature = self::derToRawSignature($derSignature);

        // 3. Pack the public half as a COSE_Key (kty=EC2, alg=ES256, crv=P-256, x, y).
        $coseKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))    // kty: EC2
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))   // alg: ES256
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))   // crv: P-256
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($details['ec']['x']))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($details['ec']['y']));

        $verifier = new BrowserBoundSignatureVerifier(Manager::create()->add(ES256::create()));

        $verifier->verify($clientDataJSON, (string) $coseKey, $rawSignature);
        // Reaching here without an exception is the contract.
        static::assertTrue(true);
    }

    #[Test]
    public function tamperedClientDataIsRejected(): void
    {
        $clientDataJSON = '{"type":"payment.get","challenge":"abc","origin":"http://localhost"}';
        $tampered = '{"type":"payment.get","challenge":"EVIL","origin":"http://localhost"}';

        $keypair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertNotFalse($keypair);
        $details = openssl_pkey_get_details($keypair);
        static::assertIsArray($details);
        openssl_sign($clientDataJSON, $derSignature, $keypair, OPENSSL_ALGO_SHA256);
        $rawSignature = self::derToRawSignature($derSignature);

        $coseKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($details['ec']['x']))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($details['ec']['y']));

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('browserBoundSignature verification failed');

        (new BrowserBoundSignatureVerifier(Manager::create()->add(ES256::create())))
            ->verify($tampered, (string) $coseKey, $rawSignature);
    }

    #[Test]
    public function unknownAlgorithmIsRejected(): void
    {
        // Build a COSE key claiming alg=-99 (unsupported).
        $coseKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-99))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create(str_repeat("\x01", 32)))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create(str_repeat("\x02", 32)));

        $this->expectException(AuthenticatorResponseVerificationException::class);

        (new BrowserBoundSignatureVerifier(Manager::create()->add(ES256::create())))
            ->verify('any', (string) $coseKey, 'any');
    }

    #[Test]
    public function knownChromeKeyShapeIsAccepted(): void
    {
        // Smoke test: the COSE key shape Chrome ships in
        // clientDataJSON.payment.browserBoundPublicKey decodes cleanly. We
        // only test the parser pathway here — the verify() itself fails
        // because we don't have the matching private key, but it must fail
        // with the *signature* error, not a parse error.
        $coseKeyB64u = 'pQECAyYgASFYIOUsBC35x2TSfRGkSeKL_uHMiWe_ptKFneJmAnIsaO4RIlggQWPJ1LAnV7OxxGq9ovhnXOqIQB7-7X6cduprsGgqEHk';
        $coseKey = Base64UrlSafe::decodeNoPadding($coseKeyB64u);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('verification failed');

        (new BrowserBoundSignatureVerifier(Manager::create()->add(ES256::create())))
            ->verify('clientData', $coseKey, str_repeat("\x00", 64));
    }

    /**
     * Convert OpenSSL's DER-encoded ECDSA signature to the raw 64-byte
     * concatenation (r || s) the COSE ES256 verifier expects.
     */
    private static function derToRawSignature(string $der): string
    {
        // Sequence header: 0x30 LL ... ; LL is the inner length.
        $offset = 2;
        if (ord($der[1]) > 0x80) {
            $offset += ord($der[1]) & 0x7F;
        }
        // r: 0x02 LR R...
        $rLen = ord($der[$offset + 1]);
        $r = substr($der, $offset + 2, $rLen);
        $offset += 2 + $rLen;
        // s: 0x02 LS S...
        $sLen = ord($der[$offset + 1]);
        $s = substr($der, $offset + 2, $sLen);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        return str_pad($r, 32, "\x00", STR_PAD_LEFT) . str_pad($s, 32, "\x00", STR_PAD_LEFT);
    }
}
