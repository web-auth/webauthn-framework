<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use ArrayIterator;
use function count;
use const COUNT_NORMAL;
use Countable;
use function is_array;
use Iterator;
use IteratorAggregate;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

/**
 * @implements IteratorAggregate<PublicKeyCredentialDescriptor>
 */
class PublicKeyCredentialDescriptorCollection implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private array $publicKeyCredentialDescriptors = [];

    public function add(PublicKeyCredentialDescriptor ...$publicKeyCredentialDescriptors): void
    {
        foreach ($publicKeyCredentialDescriptors as $publicKeyCredentialDescriptor) {
            $this->publicKeyCredentialDescriptors[$publicKeyCredentialDescriptor->getId()] = $publicKeyCredentialDescriptor;
        }
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->publicKeyCredentialDescriptors);
    }

    public function remove(string $id): void
    {
        if (! $this->has($id)) {
            return;
        }

        unset($this->publicKeyCredentialDescriptors[$id]);
    }

    /**
     * @return Iterator<string, PublicKeyCredentialDescriptor>
     */
    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->publicKeyCredentialDescriptors);
    }

    public function count(int $mode = COUNT_NORMAL): int
    {
        return count($this->publicKeyCredentialDescriptors, $mode);
    }

    /**
     * @return array<string, mixed>[]
     */
    public function jsonSerialize(): array
    {
        return array_map(
            static fn (PublicKeyCredentialDescriptor $object): array => $object->jsonSerialize(),
            $this->publicKeyCredentialDescriptors
        );
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        $collection = new self();
        foreach ($json as $item) {
            if (! is_array($item)) {
                continue;
            }
            $collection->add(PublicKeyCredentialDescriptor::createFromArray($item));
        }

        return $collection;
    }
}
