<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use JetBrains\PhpStorm\Pure;

final class RS512 extends RSA
{
    public const ID = -259;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
