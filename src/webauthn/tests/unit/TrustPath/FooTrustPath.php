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

namespace Webauthn\Tests\Unit\TrustPath;

use Webauthn\TrustPath\TrustPath;

final class FooTrustPath implements TrustPath
{
    public static function createFromArray(array $data): TrustPath
    {
        return new self();
    }

    public function jsonSerialize()
    {
        return [
            'type' => self::class,
        ];
    }
}
