<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use ArrayIterator;
use function count;
use const COUNT_NORMAL;
use Countable;
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
     * @param PublicKeyCredentialDescriptor[] $publicKeyCredentialDescriptors
     */
    public function __construct(
        public array $publicKeyCredentialDescriptors = []
    ) {
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $publicKeyCredentialDescriptors
     */
    public static function create(array $publicKeyCredentialDescriptors): self
    {
        return new self($publicKeyCredentialDescriptors);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function add(PublicKeyCredentialDescriptor ...$publicKeyCredentialDescriptors): void
    {
        foreach ($publicKeyCredentialDescriptors as $publicKeyCredentialDescriptor) {
            $this->publicKeyCredentialDescriptors[$publicKeyCredentialDescriptor->id] = $publicKeyCredentialDescriptor;
        }
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->publicKeyCredentialDescriptors);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function remove(string $id): void
    {
        if (! array_key_exists($id, $this->publicKeyCredentialDescriptors)) {
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
        return self::create(
            array_map(
                static fn (array $item): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::createFromArray(
                    $item
                ),
                $json
            )
        );
    }
}
