<?php

declare(strict_types=1);

namespace Webauthn;

use Webauthn\AttestationStatement\AttestationObject;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
 */
class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
    
    public function __construct(CollectedClientData $clientDataJSON, private AttestationObject $attestationObject)
    {
        parent::__construct($clientDataJSON);
    }

    
    public static function create(CollectedClientData $clientDataJSON, AttestationObject $attestationObject): self
    {
        return new self($clientDataJSON, $attestationObject);
    }

    
    public function getAttestationObject(): AttestationObject
    {
        return $this->attestationObject;
    }
}
