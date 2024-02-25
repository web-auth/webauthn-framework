<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use ArrayIterator;
use Countable;
use InvalidArgumentException;
use Iterator;
use IteratorAggregate;
use JsonSerializable;
use Webauthn\PublicKeyCredentialDescriptor;
use function assert;
use function count;
use function is_array;
use const COUNT_NORMAL;
use const JSON_THROW_ON_ERROR;

/**
 * @implements IteratorAggregate<PublicKeyCredentialDescriptor>
 * @internal
 */
final readonly class PublicKeyCredentialDescriptorCollection implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var array<string, PublicKeyCredentialDescriptor>
     */
    public array $publicKeyCredentialDescriptors;

    /**
     * @param PublicKeyCredentialDescriptor[] $pkCredentialDescriptors
     */
    public function __construct(
        array $pkCredentialDescriptors = []
    ) {
        $result = [];
        foreach ($pkCredentialDescriptors as $pkCredentialDescriptor) {
            $pkCredentialDescriptor instanceof PublicKeyCredentialDescriptor || throw new InvalidArgumentException(
                'Expected only instances of ' . PublicKeyCredentialDescriptor::class
            );
            $result[$pkCredentialDescriptor->id] = $pkCredentialDescriptor;
        }
        $this->publicKeyCredentialDescriptors = $result;
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $publicKeyCredentialDescriptors
     */
    public static function create(array $publicKeyCredentialDescriptors): self
    {
        return new self($publicKeyCredentialDescriptors);
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
     * @return array<string, PublicKeyCredentialDescriptor>
     */
    public function jsonSerialize(): array
    {
        return $this->publicKeyCredentialDescriptors;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, flags: JSON_THROW_ON_ERROR);
        assert(is_array($data), 'Invalid data. Expected an array of PublicKeyCredentialDescriptor');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        return self::create(
            array_map(
                static function (mixed $item): PublicKeyCredentialDescriptor {
                    assert(is_array($item), 'Invalid data. Expected an array of PublicKeyCredentialDescriptor');
                    return PublicKeyCredentialDescriptor::createFromArray($item);
                },
                $json
            )
        );
    }
}
