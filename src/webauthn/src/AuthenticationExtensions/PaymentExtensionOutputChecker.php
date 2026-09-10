<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function is_array;
use function is_string;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignature;

/**
 * Verifies the SPC `payment` extension OUTPUT. Per W3C Secure Payment
 * Confirmation §5.1, the only field returned in
 * `clientExtensionResults.payment` is `browserBoundSignature` — the bytes
 * the user agent produced with the browser-bound private key over the same
 * client data the authenticator signed.
 *
 * The actual transaction-data verification ("the user signed what the
 * merchant requested") is performed by {@see PaymentClientDataCollector}
 * against `clientDataJSON.payment`. This checker only enforces that, when
 * the request asked for the payment extension, the response carries a
 * structurally valid `browserBoundSignature` so a downstream verifier
 * (using the previously-stored {@see BrowserBoundPublicKey}) can confirm
 * it cryptographically.
 */
final readonly class PaymentExtensionOutputChecker implements ExtensionOutputChecker
{
    public function check(AuthenticationExtensions $inputs, AuthenticationExtensions $outputs): void
    {
        if (! $inputs->has('payment')) {
            return;
        }

        if (! $outputs->has('payment')) {
            throw AuthenticatorResponseVerificationException::create(
                'The payment extension was requested but not returned in the response.',
            );
        }

        $rawOutput = $outputs->get('payment')
            ->value;
        if (! is_array($rawOutput)) {
            throw AuthenticatorResponseVerificationException::create('Invalid payment extension output format.');
        }

        if (! isset($rawOutput['browserBoundSignature']) || ! is_array($rawOutput['browserBoundSignature'])) {
            throw AuthenticatorResponseVerificationException::create(
                'The payment extension output is missing the "browserBoundSignature" field.',
            );
        }

        $signature = $rawOutput['browserBoundSignature']['signature'] ?? null;
        if (! is_string($signature) || $signature === '') {
            throw AuthenticatorResponseVerificationException::create(
                'The browserBoundSignature is missing or empty.',
            );
        }

        // Decode-and-construct asserts the signature is well-formed base64url
        // bytes; throws BrowserBoundSignature's own InvalidDataException if not.
        new BrowserBoundSignature(Base64UrlSafe::decodeNoPadding($signature));
    }
}
