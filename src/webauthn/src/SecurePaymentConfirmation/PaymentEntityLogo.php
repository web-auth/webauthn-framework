<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use const FILTER_VALIDATE_URL;
use function filter_var;
use Webauthn\Exception\InvalidDataException;

/**
 * W3C Secure Payment Confirmation §5.1: PaymentEntityLogo dictionary.
 * Used in `paymentEntitiesLogos` to display payment processor / network logos
 * (e.g. Visa, MasterCard) in the SPC user confirmation UI.
 */
class PaymentEntityLogo
{
    public function __construct(
        public readonly string $url,
        public readonly string $label,
    ) {
        $url !== '' || throw InvalidDataException::create($url, 'The url must not be empty.');
        filter_var($url, FILTER_VALIDATE_URL) !== false || throw InvalidDataException::create(
            $url,
            'The url must be a valid URL.',
        );
        $label !== '' || throw InvalidDataException::create($label, 'The label must not be empty.');
    }

    public static function create(string $url, string $label): self
    {
        return new self($url, $label);
    }
}
