<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use CBOR\Decoder;
use CBOR\Normalizable;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use InvalidArgumentException;
use function sprintf;
use Throwable;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\StringStream;
use Webauthn\Util\CoseSignatureFixer;

/**
 * Cryptographically verifies the W3C SPC browser-bound signature.
 *
 * The user agent generates a browser-bound key pair, separate from the WebAuthn credential, and returns at
 * registration and at authentication:
 *   - `clientDataJSON.payment.browserBoundPublicKey`: the base64url COSE_Key of the public key;
 *   - `clientExtensionResults.payment.browserBoundSignature.signature`: the signature made with the private key
 *     over the raw `clientDataJSON` of the ceremony.
 *
 * Verification consists of:
 *   - CBOR-decoding the COSE public key bytes into a {@see Key};
 *   - looking up the matching {@see Signature} algorithm in the manager;
 *   - verifying the signature over the raw `clientDataJSON` bytes. ECDSA signatures are accepted in the ASN.1 DER
 *     form produced by the platform key stores, as for the passkey signature, or in the raw `r || s` form of COSE.
 */
final readonly class BrowserBoundSignatureVerifier
{
    public function __construct(
        private Manager $algorithmManager,
    ) {
    }

    public function verify(string $clientDataJSON, string $coseEncodedPublicKey, string $signature): void
    {
        $stream = new StringStream($coseEncodedPublicKey);
        $coseKey = Decoder::create()
            ->decode($stream);
        $stream->isEOF() || throw AuthenticatorResponseVerificationException::create(
            'Invalid browserBoundPublicKey: extra bytes after the COSE key.',
        );
        $stream->close();

        $coseKey instanceof Normalizable || throw AuthenticatorResponseVerificationException::create(
            'Invalid browserBoundPublicKey: expected a CBOR map.',
        );
        /** @var array<int|string, mixed> $coseKeyData */
        $coseKeyData = $coseKey->normalize();
        $key = Key::createFromData($coseKeyData);

        try {
            $algorithm = $this->algorithmManager->get($key->alg());
        } catch (InvalidArgumentException $e) {
            throw AuthenticatorResponseVerificationException::create(
                sprintf('Unsupported browser-bound signing algorithm "%d": %s', $key->alg(), $e->getMessage()),
            );
        }
        $algorithm instanceof Signature || throw AuthenticatorResponseVerificationException::create(
            sprintf(
                'Unsupported browser-bound signing algorithm "%d" (need a COSE Signature algorithm).',
                $key->alg(),
            ),
        );

        try {
            $verified = $algorithm->verify($clientDataJSON, $key, CoseSignatureFixer::fix($signature, $algorithm));
        } catch (Throwable $e) {
            throw AuthenticatorResponseVerificationException::create(
                'browserBoundSignature verification failed: ' . $e->getMessage(),
                $e,
            );
        }
        $verified || throw AuthenticatorResponseVerificationException::create(
            'browserBoundSignature verification failed.',
        );
    }
}
