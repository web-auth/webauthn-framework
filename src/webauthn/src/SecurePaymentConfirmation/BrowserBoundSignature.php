<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use Webauthn\Exception\InvalidDataException;

/**
 * W3C Secure Payment Confirmation §5.1: BrowserBoundSignature dictionary.
 * Returned by the user agent in `clientExtensionResults.payment.browserBoundSignature`
 * during an SPC assertion. Carries a signature produced by the browser-bound
 * private key over the same client data the authenticator signed.
 */
class BrowserBoundSignature
{
    /**
     * @param string $signature Raw signature bytes.
     */
    public function __construct(
        public readonly string $signature,
    ) {
        $signature !== '' || throw InvalidDataException::create($signature, 'The signature must not be empty.');
    }

    public static function create(string $signature): self
    {
        return new self($signature);
    }
}
