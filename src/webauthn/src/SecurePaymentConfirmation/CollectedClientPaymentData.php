<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

/**
 * W3C Secure Payment Confirmation: CollectedClientPaymentData, the client data of a ceremony made with the `payment`
 * extension. Its `payment` member is a {@see CollectedClientAdditionalPaymentRegistrationData} at registration
 * (`webauthn.create`) and a {@see CollectedClientAdditionalPaymentData} at authentication (`payment.get`). Both carry
 * the browser-bound public key, when the user agent has one.
 *
 * Denormalize the client data of a response into this class to read them, for instance
 * `$serializer->denormalize($authenticatorResponse->clientDataJSON->data, CollectedClientPaymentData::class)`.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-collectedclientpaymentdata-dictionary
 */
class CollectedClientPaymentData
{
    public function __construct(
        public readonly CollectedClientAdditionalPaymentData|CollectedClientAdditionalPaymentRegistrationData $payment,
    ) {
    }

    public static function create(
        CollectedClientAdditionalPaymentData|CollectedClientAdditionalPaymentRegistrationData $payment
    ): self {
        return new self($payment);
    }
}
