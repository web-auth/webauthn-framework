<?php

declare(strict_types=1);

namespace Cose\Algorithm\Mac;

use Assert\Assertion;
use Cose\Key\Key;

abstract class Hmac implements Mac
{
    public function hash(string $data, Key $key): string
    {
        $this->checKey($key);
        $signature = hash_hmac($this->getHashAlgorithm(), $data, $key->get(-1), true);

        return mb_substr($signature, 0, $this->getSignatureLength() / 8, '8bit');
    }

    public function verify(string $data, Key $key, string $signature): bool
    {
        return hash_equals($this->hash($data, $key), $signature);
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignatureLength(): int;

    private function checKey(Key $key): void
    {
        Assertion::eq($key->type(), 4, 'Invalid key. Must be of type symmetric');
        Assertion::true($key->has(-1), 'Invalid key. The value of the key is missing');
    }
}
