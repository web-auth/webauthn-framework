<?php

declare(strict_types=1);

namespace Webauthn;

use JetBrains\PhpStorm\Pure;

/**
 * @see https://www.w3.org/TR/webauthn/#authenticatorresponse
 */
abstract class AuthenticatorResponse
{
    #[Pure]
    public function __construct(private CollectedClientData $clientDataJSON)
    {
    }

    #[Pure]
    public function getClientDataJSON(): CollectedClientData
    {
        return $this->clientDataJSON;
    }
}
