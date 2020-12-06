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

namespace Webauthn\Exception;

use Throwable;

final class InvalidAttestationObjectException extends WebauthnException
{
    public static function create(string $message, ?Throwable $previous = null): callable
    {
        return static function () use ($message, $previous): self {
            return new self($message, $previous);
        };
    }
}
