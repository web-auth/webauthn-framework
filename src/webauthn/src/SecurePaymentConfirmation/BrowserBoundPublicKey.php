<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use Webauthn\Exception\InvalidDataException;

/**
 * W3C Secure Payment Confirmation §5.1: BrowserBoundPublicKey dictionary.
 * Returned in `clientDataJSON.payment.browserBoundPublicKey` during an SPC
 * registration ceremony. The relying party SHOULD store this key alongside
 * the credential record so subsequent assertion `browserBoundSignature`
 * outputs can be verified.
 */
class BrowserBoundPublicKey
{
    /**
     * @param string $publicKey COSE-encoded raw public key bytes.
     * @param int    $algorithm COSE algorithm identifier (e.g. -7 for ES256).
     */
    public function __construct(
        public readonly string $publicKey,
        public readonly int $algorithm,
    ) {
        $publicKey !== '' || throw InvalidDataException::create($publicKey, 'The publicKey must not be empty.');
    }

    public static function create(string $publicKey, int $algorithm): self
    {
        return new self($publicKey, $algorithm);
    }
}
