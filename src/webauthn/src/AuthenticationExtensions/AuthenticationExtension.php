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

use JsonSerializable;

class AuthenticationExtension implements JsonSerializable
{
    public function __construct(
        private string $name,
        private $value
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function value()
    {
        return $this->value;
    }

    public function jsonSerialize()
    {
        return $this->value;
    }
}
