<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * Rejects a `payment` entry found in the AUTHENTICATOR extension outputs.
 *
 * The W3C Secure Payment Confirmation `payment` extension has no authenticator extension processing. Its only output,
 * the browser-bound signature, is a client extension result, and the browser-bound public key travels in the client
 * data: both are verified by {@see \Webauthn\CeremonyStep\CheckBrowserBoundSignature}, which every ceremony built by
 * {@see \Webauthn\CeremonyStep\CeremonyStepManagerFactory} runs. A `payment` entry in the authenticator data is never
 * produced by a conforming authenticator, and its value must not be mistaken for the client output.
 *
 * Other authenticator extension outputs, such as `credProtect`, are left to their own checkers.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-payment-extension-registration
 */
final readonly class PaymentExtensionOutputChecker implements ExtensionOutputChecker
{
    public function check(AuthenticationExtensions $inputs, AuthenticationExtensions $outputs): void
    {
        if (! $outputs->has('payment')) {
            return;
        }

        throw AuthenticatorResponseVerificationException::create(
            'The authenticator extension outputs must not contain a "payment" entry. The Secure Payment Confirmation outputs are client extension results.',
        );
    }
}
