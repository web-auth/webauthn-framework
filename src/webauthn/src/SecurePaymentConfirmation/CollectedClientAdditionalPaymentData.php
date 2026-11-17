<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use const FILTER_VALIDATE_URL;
use function filter_var;
use Webauthn\Exception\InvalidDataException;

/**
 * W3C Secure Payment Confirmation §5.1: CollectedClientAdditionalPaymentData.
 * Encapsulates the payment confirmation data the authenticator signs as part
 * of the `clientDataJSON.payment` field.
 */
class CollectedClientAdditionalPaymentData
{
    /**
     * @param PaymentEntityLogo[] $paymentEntitiesLogos
     */
    public function __construct(
        public readonly string $rpId,
        public readonly string $topOrigin,
        public readonly PaymentCurrencyAmount $total,
        public readonly PaymentCredentialInstrument $instrument,
        public readonly string $payeeName = '',
        public readonly string $payeeOrigin = '',
        public readonly array $paymentEntitiesLogos = [],
        public readonly ?BrowserBoundPublicKey $browserBoundPublicKey = null,
    ) {
        $rpId !== '' || throw InvalidDataException::create($rpId, 'The rpId must not be empty.');
        $topOrigin !== '' || throw InvalidDataException::create($topOrigin, 'The topOrigin must not be empty.');
        filter_var($topOrigin, FILTER_VALIDATE_URL) !== false || throw InvalidDataException::create(
            $topOrigin,
            'The topOrigin must be a valid URL.',
        );
        if ($payeeOrigin !== '') {
            filter_var($payeeOrigin, FILTER_VALIDATE_URL) !== false || throw InvalidDataException::create(
                $payeeOrigin,
                'The payeeOrigin must be a valid URL.',
            );
        }
    }

    /**
     * @param PaymentEntityLogo[] $paymentEntitiesLogos
     */
    public static function create(
        string $rpId,
        string $topOrigin,
        PaymentCurrencyAmount $total,
        PaymentCredentialInstrument $instrument,
        string $payeeName = '',
        string $payeeOrigin = '',
        array $paymentEntitiesLogos = [],
        ?BrowserBoundPublicKey $browserBoundPublicKey = null,
    ): self {
        return new self(
            $rpId,
            $topOrigin,
            $total,
            $instrument,
            $payeeName,
            $payeeOrigin,
            $paymentEntitiesLogos,
            $browserBoundPublicKey,
        );
    }
}
