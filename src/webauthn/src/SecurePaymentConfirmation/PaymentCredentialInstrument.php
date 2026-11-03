<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use const FILTER_VALIDATE_URL;
use function filter_var;
use Webauthn\Exception\InvalidDataException;

class PaymentCredentialInstrument
{
    public function __construct(
        public readonly string $displayName,
        public readonly string $icon,
        public readonly bool $iconMustBeShown = true,
        public readonly ?string $details = null,
    ) {
        $displayName !== '' || throw InvalidDataException::create($displayName, 'The displayName must not be empty.');
        $icon !== '' || throw InvalidDataException::create($icon, 'The icon must not be empty.');
        filter_var($icon, FILTER_VALIDATE_URL) !== false || throw InvalidDataException::create(
            $icon,
            'The icon must be a valid URL.',
        );
    }

    public static function create(
        string $displayName,
        string $icon,
        bool $iconMustBeShown = true,
        ?string $details = null,
    ): self {
        return new self($displayName, $icon, $iconMustBeShown, $details);
    }
}
