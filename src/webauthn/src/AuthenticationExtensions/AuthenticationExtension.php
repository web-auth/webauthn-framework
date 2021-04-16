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

use JetBrains\PhpStorm\Pure;
use JsonSerializable;

class AuthenticationExtension implements JsonSerializable
{
    #[Pure]
    public function __construct(private string $name, private mixed $value)
    {
    }

    #[Pure]
    public function name(): string
    {
        return $this->name;
    }

    #[Pure]
    public function value(): mixed
    {
        return $this->value;
    }

    #[Pure]
    public function jsonSerialize(): mixed
    {
        return $this->value;
    }
}
