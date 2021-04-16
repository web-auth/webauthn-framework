<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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
