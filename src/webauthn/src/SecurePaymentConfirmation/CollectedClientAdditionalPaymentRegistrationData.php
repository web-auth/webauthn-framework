<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

/**
 * W3C Secure Payment Confirmation: CollectedClientAdditionalPaymentRegistrationData.
 * The `clientDataJSON.payment` member of a registration made with the `payment` extension. It only carries the
 * browser-bound public key, which the user agent omits when it has no browser-bound key.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-collectedclientadditionalpaymentregistrationdata-dictionary
 */
class CollectedClientAdditionalPaymentRegistrationData
{
    public function __construct(
        public readonly ?BrowserBoundPublicKey $browserBoundPublicKey = null,
    ) {
    }

    public static function create(?BrowserBoundPublicKey $browserBoundPublicKey = null): self
    {
        return new self($browserBoundPublicKey);
    }
}
