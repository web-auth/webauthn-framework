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

namespace Webauthn\AuthenticationExtensions;

use Assert\Assertion;

class AuthenticationExtensionsClientOutputs implements \JsonSerializable, \Countable, \IteratorAggregate
{
    /**
     * @var AuthenticationExtension[]
     */
    private $extensions = [];

    public function add(AuthenticationExtension $extension): void
    {
        $this->extensions[$extension->name()] = $extension;
    }

    /**
     * @deprecated will be removed in v2.0. Use "createFromArray" instead
     */
    public static function createFromJson(array $json): self
    {
        return self::createFromArray($json);
    }

    public static function createFromString(string $data): self
    {
        $data = \Safe\json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromArray(array $json): self
    {
        $object = new self();
        foreach ($json as $k => $v) {
            $object->add(new AuthenticationExtension($k, $v));
        }

        return $object;
    }

    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->extensions);
    }

    /**
     * @return mixed
     */
    public function get(string $key)
    {
        Assertion::true($this->has($key), \Safe\sprintf('The extension with key "%s" is not available', $key));

        return $this->extensions[$key];
    }

    public function jsonSerialize(): array
    {
        return $this->extensions;
    }

    public function getIterator(): \Iterator
    {
        return new \ArrayIterator($this->extensions);
    }

    public function count(int $mode = COUNT_NORMAL): int
    {
        return \count($this->extensions, $mode);
    }
}
