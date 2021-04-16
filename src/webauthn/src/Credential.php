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
 * @see https://w3c.github.io/webappsec-credential-management/#credential
 */
abstract class Credential
{
    #[Pure]
    public function __construct(protected string $id, protected string $type)
    {
    }

    #[Pure]
    public function getId(): string
    {
        return $this->id;
    }

    #[Pure]
    public function getType(): string
    {
        return $this->type;
    }
}
