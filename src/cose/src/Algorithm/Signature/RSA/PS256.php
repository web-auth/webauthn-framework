<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Jose\Component\Core\Util\Hash;

final class PS256 extends PSSRSA
{
    public const ID = -37;

    
    public static function identifier(): int
    {
        return self::ID;
    }

    
    protected function getHashAlgorithm(): Hash
    {
        return Hash::sha256();
    }
}
