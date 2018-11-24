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

class AuthenticationExtensionsClientOutputs implements \JsonSerializable, \Countable, \IteratorAggregate
{
    /**
     * @var AuthenticationExtension[]
     */
    private $extensions = [];

    public function add(AuthenticationExtension $extension)
    {
        $this->extensions[$extension->name()] = $extension;
    }

    public function jsonSerialize()
    {
        return $this->extensions;
    }

    public function getIterator()
    {
        return new \ArrayIterator($this->extensions);
    }

    public function count($mode = COUNT_NORMAL): int
    {
        return \count($this->extensions, $mode);
    }
}
