<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use JetBrains\PhpStorm\Pure;

final class RS384 extends RSA
{
    public const ID = -258;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
}
