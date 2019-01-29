<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Cose\Algorithm\Signature\ECDSA;

use Assert\Assertion;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Ec2Key;
use Cose\Key\Key;

abstract class ECDSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        return 1 === openssl_verify($data, $signature, $key->asPEM(), $this->getHashAlgorithm());
    }

    private function handleKey(Key $key): Ec2Key
    {
        $key = new Ec2Key($key->getData());
        Assertion::eq($key->curve(), $this->getCurve(), 'This key cannot be used with this algorithm');

        return $key;
    }

    abstract protected function getCurve(): int;

    abstract protected function getHashAlgorithm(): int;
}
