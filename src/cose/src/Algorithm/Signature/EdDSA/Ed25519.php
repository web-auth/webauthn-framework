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

namespace Cose\Algorithm\Signature\EdDSA;

use JetBrains\PhpStorm\Pure;

final class Ed25519 extends EdDSA
{
    public const ID = -8;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }
}
