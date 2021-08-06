<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\ECDSA;

use Cose\Key\Ec2Key;
use JetBrains\PhpStorm\Pure;

final class ES256 extends ECDSA
{
    public const ID = -7;

    #[Pure]
    public static function identifier(): int
    {
        return self::ID;
    }

    #[Pure]
    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    #[Pure]
    protected function getCurve(): int
    {
        return Ec2Key::CURVE_P256;
    }

    #[Pure]
    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
