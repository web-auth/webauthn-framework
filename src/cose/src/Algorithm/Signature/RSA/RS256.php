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

namespace Cose\Algorithm\Signature\RSA;

final class RS256 extends RSA
{
    public static function identifier(): int
    {
        return -257;
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
}
