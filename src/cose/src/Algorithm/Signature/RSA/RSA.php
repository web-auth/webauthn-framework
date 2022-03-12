<?php

declare(strict_types=1);

namespace Cose\Algorithm\Signature\RSA;

use Assert\Assertion;
use Cose\Algorithm\Signature\Signature;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use InvalidArgumentException;

abstract class RSA implements Signature
{
    public function sign(string $data, Key $key): string
    {
        $key = $this->handleKey($key);
        Assertion::true($key->isPrivate(), 'The key is not private');

        if (openssl_sign($data, $signature, $key->asPem(), $this->getHashAlgorithm()) === false) {
            throw new InvalidArgumentException('Unable to sign the data');
        }

        return $signature;
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        $key = $this->handleKey($key);

        return openssl_verify($data, $signature, $key->asPem(), $this->getHashAlgorithm()) === 1;
    }

    abstract protected function getHashAlgorithm(): int;

    private function handleKey(Key $key): RsaKey
    {
        return RsaKey::create($key->getData());
    }
}
