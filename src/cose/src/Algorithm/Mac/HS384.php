<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use JetBrains\PhpStorm\Pure;

final class HS384 extends Hmac
{
    public const ID = 6;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): string
    {
        return 'sha384';
    }

    #[Pure]
    protected function getSignatureLength(): int
    {
        return 384;
    }
}
