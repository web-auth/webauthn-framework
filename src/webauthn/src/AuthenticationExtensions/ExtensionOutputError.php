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

namespace Webauthn\AuthenticationExtensions;

use Exception;
use JetBrains\PhpStorm\Pure;
use Throwable;

class ExtensionOutputError extends Exception
{
    #[Pure]
    public function __construct(private AuthenticationExtension $authenticationExtension, string $message = '', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    #[Pure]
    public function getAuthenticationExtension(): AuthenticationExtension
    {
        return $this->authenticationExtension;
    }
}
