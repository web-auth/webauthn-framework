<?php

declare(strict_types=1);

namespace Webauthn;

use JetBrains\PhpStorm\Pure;
use Webauthn\AttestationStatement\AttestationObject;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    #[Pure]
    public function __construct(CollectedClientData $clientDataJSON, private AttestationObject $attestationObject)
    {
        parent::__construct($clientDataJSON);
    }

    #[Pure]
    public static function create(CollectedClientData $clientDataJSON, AttestationObject $attestationObject): self
    {
        return new self($clientDataJSON, $attestationObject);
    }

    #[Pure]
    public function getAttestationObject(): AttestationObject
    {
        return $this->attestationObject;
    }
}
