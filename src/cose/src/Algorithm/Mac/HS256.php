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

namespace Cose\Algorithm\Mac;

use Cose\Algorithms;

final class HS256 extends Hmac
{
    public static function identifier(): int
    {
        return Algorithms::COSE_ALGORITHM_HS256;
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function getSignatureLength(): int
    {
        return 256;
    }
}
