<?php

declare(strict_types=1);

namespace Cose\Algorithm;

use Assert\Assertion;

class ManagerFactory
{
    /**
     * @var Algorithm[]
     */
    private array $algorithms = [];

    public function add(string $alias, Algorithm $algorithm): self
    {
        $this->algorithms[$alias] = $algorithm;

        return $this;
    }

    public function list(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    public function all(): iterable
    {
        yield from array_keys($this->algorithms);
    }

    public function create(array $aliases): Manager
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
