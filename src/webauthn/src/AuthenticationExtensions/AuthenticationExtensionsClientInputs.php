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

namespace Webauthn\AuthenticationExtensions;

class AuthenticationExtensionsClientInputs implements \JsonSerializable, \Countable, \IteratorAggregate
{
    /**
     * @var AuthenticationExtension[]
     */
    private $extensions = [];

    public function add(AuthenticationExtension $extension): void
    {
        $this->extensions[$extension->name()] = $extension;
    }

    public static function createFromJson(array $json): self
    {
        $object = new self();
        foreach ($json as $k => $v) {
            $object->add(new AuthenticationExtension($k, $v));
        }

        return $object;
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