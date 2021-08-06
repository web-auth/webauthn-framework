<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\ECDSA;

use Cose\Key\Ec2Key;
use JetBrains\PhpStorm\Pure;

final class ES384 extends ECDSA
{
    public const ID = -35;

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

    #[Pure]
    protected function getCurve(): int
    {
        return Ec2Key::CURVE_P384;
    }

    #[Pure]
    protected function getSignaturePartLength(): int
    {
        return 96;
    }
}
