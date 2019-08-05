<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Signature\EdDSA;

use Cose\Algorithms;
use Cose\Key\Key;

final class ED512 extends EdDSA
{
    public function sign(string $data, Key $key): string
    {
        $hashedData = hash('sha512', $data, true);

        return parent::sign($hashedData, $key);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $hashedData = hash('sha512', $data, true);

        return parent::verify($hashedData, $key, $signature);
    }

    public static function identifier(): int
    {
        return Algorithms::COSE_ALGORITHM_ED512;
    }
}
