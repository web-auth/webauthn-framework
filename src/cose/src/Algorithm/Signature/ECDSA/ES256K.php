<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Signature\ECDSA;

use Cose\Key\Ec2Key;
use Cose\Key\Key;

final class ES256K extends ECDSA
{
    public const ID = -43;

    public static function identifier(): int
    {
        return self::ID;
    }

    public function sign(string $data, Key $key): string
    {
        $signature = parent::sign($data, $key);

        return ECSignature::fromAsn1($signature, 64);
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $signature = ECSignature::toAsn1($signature, 64);

        return parent::verify($data, $key, $signature);
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function getCurve(): int
    {
        return Ec2Key::CURVE_P256K;
    }
}
