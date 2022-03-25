<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use Assert\Assertion;

final class ManagerFactory
{
    /**
     * @var array<string, Algorithm>
     */
    private array $algorithms = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(string $alias, Algorithm $algorithm): self
    {
        $this->algorithms[$alias] = $algorithm;

        return $this;
    }

    /**
     * @return string[]
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

    public function generate(string ...$aliases): Manager
    {
        $manager = Manager::create();
        foreach ($aliases as $alias) {
            Assertion::keyExists(
                $this->algorithms,
                $alias,
                sprintf('The algorithm with alias "%s" is not supported', $alias)
            );
            $manager->add($this->algorithms[$alias]);
        }

        return $manager;
    }
}
