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

namespace Cose\Algorithm\Mac;

use JetBrains\PhpStorm\Pure;

final class HS256 extends Hmac
{
    public const ID = 5;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    #[Pure]
    protected function getSignatureLength(): int
    {
        return 256;
    }
}
