<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use JetBrains\PhpStorm\Pure;

final class HS256Truncated64 extends Hmac
{
    public const ID = 4;

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
        return 64;
    }
}
