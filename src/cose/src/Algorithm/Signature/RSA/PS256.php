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

namespace Cose\Algorithm\Signature\RSA;

use JetBrains\PhpStorm\Pure;
use Jose\Component\Core\Util\Hash;

final class PS256 extends PSSRSA
{
    public const ID = -37;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): Hash
    {
        return Hash::sha256();
    }
}
