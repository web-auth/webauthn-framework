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

namespace Cose\Algorithm\Signature\EdDSA;

use Assert\Assertion;
use Cose\Algorithm\Signature\Signature;
use Cose\Algorithms;
use Cose\Key\Key;
use Cose\Key\OkpKey;

final class EdDSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        Assertion::true($key->isPrivate(), 'The key is not private');

        $keyPair = \sodium_crypto_sign_seed_keypair($key->d());
        $secretKey = \sodium_crypto_sign_secretkey($keyPair);

        switch ($key->curve()) {
            case OkpKey::CURVE_ED25519:
                return \sodium_crypto_sign_detached($data, $secretKey);
            default:
                throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        switch ($key->curve()) {
            case OkpKey::CURVE_ED25519:
                return \sodium_crypto_sign_verify_detached($signature, $data, $key->x());
            default:
                throw new \InvalidArgumentException('Unsupported curve');
        }
    }

    public static function identifier(): int
    {
        return Algorithms::COSE_ALGORITHM_EdDSA;
    }

    private function handleKey(Key $key): OkpKey
    {
        return new OkpKey($key->getData());
    }
}
