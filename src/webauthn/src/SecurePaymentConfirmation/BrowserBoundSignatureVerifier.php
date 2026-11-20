<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\Signature;
use InvalidArgumentException;
use function sprintf;
use Throwable;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\InvalidDataException;
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
 *   - decoding the COSE public key bytes with {@see BrowserBoundPublicKey::coseKey()}, the decoding behind
 *     {@see BrowserBoundPublicKey::algorithm()}, so that a key without an integer `alg` member is refused;
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
        try {
            $publicKey = BrowserBoundPublicKey::create($coseEncodedPublicKey);
            $key = $publicKey->coseKey();
            $algorithmIdentifier = $publicKey->algorithm();
        } catch (InvalidDataException $e) {
            throw AuthenticatorResponseVerificationException::create($e->getMessage(), $e);
        }

        try {
            $algorithm = $this->algorithmManager->get($algorithmIdentifier);
        } catch (InvalidArgumentException $e) {
            throw AuthenticatorResponseVerificationException::create(
                sprintf('Unsupported browser-bound signing algorithm "%d": %s', $algorithmIdentifier, $e->getMessage()),
            );
        }
        $algorithm instanceof Signature || throw AuthenticatorResponseVerificationException::create(
            sprintf(
                'Unsupported browser-bound signing algorithm "%d" (need a COSE Signature algorithm).',
                $algorithmIdentifier,
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
