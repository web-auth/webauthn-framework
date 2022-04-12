<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AttestationStatement\AttestationObject;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    public function __construct(
        CollectedClientData $clientDataJSON,
        private readonly AttestationObject $attestationObject
    ) {
        parent::__construct($clientDataJSON);
    }

    public function getAttestationObject(): AttestationObject
    {
        return $this->attestationObject;
    }
}
