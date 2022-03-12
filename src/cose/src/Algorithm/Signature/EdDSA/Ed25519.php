<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\EdDSA;


final class Ed25519 extends EdDSA
{
    public const ID = -8;

    
    public static function identifier(): int
    {
        return self::ID;
    }
}
