<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use Webauthn\Exception\InvalidDataException;

/**
 * W3C Secure Payment Confirmation: the browser-bound public key.
 *
 * The client data carries it in `payment.browserBoundPublicKey`, at registration and at authentication, as the
 * base64url encoding of a COSE_Key, encoded like the credential public key of the attested credential data. This
 * object holds the decoded COSE_Key bytes: the algorithm of the key is its `alg` member. The serializer reads and
 * writes the base64url string.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-collectedclientadditionalpaymentdata-dictionary
 */
class BrowserBoundPublicKey
{
    /**
     * @param string $publicKey COSE_Key bytes
     */
    public function __construct(
        public readonly string $publicKey,
    ) {
        $publicKey !== '' || throw InvalidDataException::create(
            $publicKey,
            'The browser-bound public key must not be empty.'
        );
    }

    public static function create(string $publicKey): self
    {
        return new self($publicKey);
    }
}
