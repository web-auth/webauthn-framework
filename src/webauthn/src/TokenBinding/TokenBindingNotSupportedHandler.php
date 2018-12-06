<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\TokenBinding;

use Assert\Assertion;
use Symfony\Component\HttpFoundation\Request;

final class TokenBindingNotSupportedHandler implements TokenBindingHandler
{
    public function check(TokenBinding $tokenBinding, Request $request): void
    {
        Assertion::true(TokenBinding::TOKEN_BINDING_STATUS_PRESENT !== $tokenBinding->getStatus(), 'Token binding not supported.');
    }
}
