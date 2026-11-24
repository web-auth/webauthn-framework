<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

class CollectedClientPaymentData
{
    public function __construct(
        public readonly CollectedClientAdditionalPaymentData $payment,
    ) {
    }

    public static function create(CollectedClientAdditionalPaymentData $payment): self
    {
        return new self($payment);
    }
}
