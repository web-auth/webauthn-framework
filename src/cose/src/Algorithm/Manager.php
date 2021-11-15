<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use function array_key_exists;
use Assert\Assertion;

class Manager
{
    /**
     * @var Algorithm[]
     */
    private array $algorithms = [];

    public function add(Algorithm $algorithm): void
    {
        $identifier = $algorithm::identifier();
        $this->algorithms[$identifier] = $algorithm;
    }

    public function list(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    /**
     * @return Algorithm[]
     */
    public function all(): iterable
    {
        yield from $this->algorithms;
    }

    public function has(int $identifier): bool
    {
        return array_key_exists($identifier, $this->algorithms);
    }

    public function get(int $identifier): Algorithm
    {
        Assertion::true($this->has($identifier), 'Unsupported algorithm');

        return $this->algorithms[$identifier];
    }
}
