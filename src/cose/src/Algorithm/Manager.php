<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use function array_key_exists;
use Assert\Assertion;

final class Manager
{
    /**
     * @var array<int, Algorithm>
     */
    private array $algorithms = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(Algorithm ...$algorithms): self
    {
        foreach ($algorithms as $algorithm) {
            $identifier = $algorithm::identifier();
            $this->algorithms[$identifier] = $algorithm;
        }

        return $this;
    }

    /**
     * @return int[]
     */
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
