<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use JetBrains\PhpStorm\Pure;
use Jose\Component\Core\Util\Hash;

final class PS384 extends PSSRSA
{
    public const ID = -38;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): Hash
    {
        return Hash::sha384();
    }
}
