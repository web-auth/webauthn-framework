<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use function array_key_exists;
use Assert\Assertion;
use JetBrains\PhpStorm\Pure;

class Manager
{
    /**
     * @var Algorithm[]
     */
    private array $algorithms = [];

    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    public function add(Algorithm $algorithm): self
    {
        $identifier = $algorithm::identifier();
        $this->algorithms[$identifier] = $algorithm;

        return $this;
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

    #[Pure]
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
