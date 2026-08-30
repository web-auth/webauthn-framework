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

/**
 * Cryptographically verifies the W3C SPC `browserBoundSignature`.
 *
 * Per W3C Secure Payment Confirmation §5.1, the user agent generates a
 * browser-bound key pair separate from the WebAuthn credential. During an
 * SPC assertion it returns:
 *
 *   - `clientExtensionResults.payment.browserBoundSignature.signature` —
 *     the signature produced by the browser-bound private key over the
 *     `clientDataJSON` of the WebAuthn ceremony;
 *   - in Chrome's implementation, also
 *     `clientDataJSON.payment.browserBoundPublicKey` — the matching
 *     COSE-encoded public key, sent on every assertion so the relying party
 *     can verify without having stashed it from registration.
 *
 * Verification consists of:
 *   - CBOR-decoding the COSE public key bytes into a {@see Key};
 *   - looking up the matching {@see Signature} algorithm in the manager;
 *   - verifying the signature over the raw `clientDataJSON` bytes.
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
            $verified = $algorithm->verify($clientDataJSON, $key, $signature);
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
