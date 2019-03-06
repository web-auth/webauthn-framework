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

namespace Cose\Algorithm;

use Assert\Assertion;

class Manager
{
    /**
     * @var Algorithm[]
     */
    private $algorithms = [];

    public function add(Algorithm $algorithm): void
    {
        $identifier = $algorithm::identifier();
        $this->algorithms[$identifier] = $algorithm;
    }

    public function getAlgorithms(): iterable
    {
        yield from $this->algorithms;
    }

    public function has(int $identifier): bool
    {
        return \array_key_exists($identifier, $this->algorithms);
    }

    public function get(int $identifier): Algorithm
    {
        Assertion::true($this->has($identifier), 'Unsupported algorithm');

        return $this->algorithms[$identifier];
    }
}
