<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use ArrayIterator;
use Assert\Assertion;
use function count;
use Countable;
use Iterator;
use IteratorAggregate;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\json_decode;

class PublicKeyCredentialDescriptorCollection implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private array $publicKeyCredentialDescriptors = [];

    public function add(PublicKeyCredentialDescriptor $publicKeyCredentialDescriptor): self
    {
        $this->publicKeyCredentialDescriptors[$publicKeyCredentialDescriptor->getId()] = $publicKeyCredentialDescriptor;

        return $this;
    }

    #[Pure]
    public function has(string $id): bool
    {
        return array_key_exists($id, $this->publicKeyCredentialDescriptors);
    }

    public function remove(string $id): self
    {
        if (!$this->has($id)) {
            return $this;
        }

        unset($this->publicKeyCredentialDescriptors[$id]);

        return $this;
    }

    /**
     * @return Iterator<string, PublicKeyCredentialDescriptor>
     */
    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->publicKeyCredentialDescriptors);
    }

    #[Pure]
    public function count(int $mode = COUNT_NORMAL): int
    {
        return count($this->publicKeyCredentialDescriptors, $mode);
    }

    /**
     * @return array[]
     */
    public function jsonSerialize(): array
    {
        return array_map(static function (PublicKeyCredentialDescriptor $object): array {
            return $object->jsonSerialize();
        }, $this->publicKeyCredentialDescriptors);
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        $collection = new self();
        foreach ($json as $item) {
            $collection->add(PublicKeyCredentialDescriptor::createFromArray($item));
        }

        return $collection;
    }
}
