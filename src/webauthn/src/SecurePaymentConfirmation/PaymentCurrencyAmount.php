<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use function preg_match;
use Webauthn\Exception\InvalidDataException;

class PaymentCurrencyAmount
{
    /**
     * Per W3C Payment Request API: ISO-4217 alphabetic code, 3 uppercase letters.
     */
    private const CURRENCY_PATTERN = '/^[A-Z]{3}$/';

    /**
     * Per W3C Payment Request API §StandardizedDigits: signed decimal monetary value.
     */
    private const VALUE_PATTERN = '/^-?[0-9]+(\.[0-9]+)?$/';

    public function __construct(
        public readonly string $currency,
        public readonly string $value,
    ) {
        preg_match(self::CURRENCY_PATTERN, $currency) === 1 || throw InvalidDataException::create(
            $currency,
            'The currency must be a 3-letter ISO 4217 alphabetic code (e.g. "USD", "EUR").',
        );
        preg_match(self::VALUE_PATTERN, $value) === 1 || throw InvalidDataException::create(
            $value,
            'The value must be a decimal monetary amount (e.g. "9.99", "-100", "0.5").',
        );
    }

    public static function create(string $currency, string $value): self
    {
        return new self($currency, $value);
    }
}
