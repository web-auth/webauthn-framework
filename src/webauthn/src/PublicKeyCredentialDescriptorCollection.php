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

namespace Webauthn;

class PublicKeyCredentialDescriptorCollection implements \JsonSerializable, \Countable, \IteratorAggregate
{
    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $publicKeyCredentialDescriptors = [];

    public function add(PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor): void
    {
        $this->publicKeyCredentialDescriptors[$publicKeyCredentialDescriptor->getId()] = $publicKeyCredentialDescriptor;
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->publicKeyCredentialDescriptors);
    }

    public function remove(string $id): void
    {
        if (!$this->has($id)) {
            return;
        }

        unset($this->publicKeyCredentialDescriptors[$id]);
    }

    public function getIterator(): \Iterator
    {
        return new \ArrayIterator($this->publicKeyCredentialDescriptors);
    }

    public function count(int $mode = COUNT_NORMAL): int
    {
        return \count($this->publicKeyCredentialDescriptors, $mode);
    }

    public function jsonSerialize(): array
    {
        return array_values($this->publicKeyCredentialDescriptors);
    }

    public static function createFromJson(array $json): self
    {
        $collection = new self();
        foreach ($json as $item) {
            $collection->add(PublicKeyCredentialDescriptor::createFromJson($item));
        }

        return $collection;
    }
}
