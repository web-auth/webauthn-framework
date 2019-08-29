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

final class ES256 extends ECDSA
{
    public const ID = -7;

    public static function identifier(): int
    {
        return self::ID;
    }

    public function sign(string $data, Key $key): string
    {
        $signature = parent::sign($data, $key);

        return ECSignature::fromAsn1($signature, $this->getSignaturePartLength());
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $signature = ECSignature::toAsn1($signature, $this->getSignaturePartLength());

        return parent::verify($data, $key, $signature);
    }

    protected function getHashAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function getCurve(): int
    {
        return Ec2Key::CURVE_P256;
    }

    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
