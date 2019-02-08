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

namespace Cose\Key;

use Assert\Assertion;

class Key
{
    public const TYPE = 1;
    public const KID = 2;
    public const ALG = 3;
    public const KEY_OPS = 4;
    public const BASE_IV = 5;

    /**
     * @var array
     */
    private $data;

    public function __construct(array $data)
    {
        Assertion::keyExists($data, self::TYPE, 'Invalid key: the type is not defined');
        $this->data = $data;
    }

    /**
     * @return int|string
     */
    public function type()
    {
        return $this->data[self::TYPE];
    }

    public function alg(): int
    {
        return (int) $this->get(self::ALG);
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function has(int $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @return mixed
     */
    public function get(int $key)
    {
        Assertion::keyExists($this->data, $key, \Safe\sprintf('The key has no data at index %d', $key));

        return $this->data[$key];
    }
}
