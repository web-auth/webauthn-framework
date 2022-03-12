<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;


final class RS256 extends RSA
{
    public const ID = -257;

    
    public static function identifier(): int
    {
        return self::ID;
    }

    
    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }
}
