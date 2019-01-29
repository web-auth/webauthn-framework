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

final class HS384 extends Hmac
{
    public static function identifier(): int
    {
        return 6;
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function getSignatureLength(): int
    {
        return 384;
    }
}
