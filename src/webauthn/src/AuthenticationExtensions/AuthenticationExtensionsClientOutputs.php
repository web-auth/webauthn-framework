<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use function array_key_exists;
use ArrayIterator;
use function count;
use const COUNT_NORMAL;
use Countable;
use Iterator;
use IteratorAggregate;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @implements IteratorAggregate<AuthenticationExtension>
 */
class AuthenticationExtensionsClientOutputs implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var AuthenticationExtension[]
     */
    public array $extensions = [];

    /**
     * @param AuthenticationExtension[] $extensions
     */
    public function __construct(array $extensions = [])
    {
        foreach ($extensions as $extension) {
            $this->extensions[$extension->name] = $extension;
        }
    }

    /**
     * @param AuthenticationExtension[] $extensions
     */
    public static function create(array $extensions = []): self
    {
        return new self($extensions);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function add(AuthenticationExtension ...$extensions): void
    {
        foreach ($extensions as $extension) {
            $this->extensions[$extension->name] = $extension;
        }
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param array<string, mixed> $json
     */
    public static function createFromArray(array $json): self
    {
        return self::create(
            array_map(
                static fn (string $key, mixed $value): AuthenticationExtension => AuthenticationExtension::create(
                    $key,
                    $value
                ),
                array_keys($json),
                $json
            )
        );
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->extensions);
    }

    public function get(string $key): AuthenticationExtension
    {
        $this->has($key) || throw AuthenticationExtensionException::create(sprintf(
            'The extension with key "%s" is not available',
            $key
        ));

        return $this->extensions[$key];
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return array_map(
            static fn (AuthenticationExtension $object): mixed => $object->jsonSerialize(),
            $this->extensions
        );
    }

    /**
     * @return Iterator<string, AuthenticationExtension>
     */
    public function getIterator(): Iterator
    {
        return new ArrayIterator($this->extensions);
    }

    public function count(int $mode = COUNT_NORMAL): int
    {
        return count($this->extensions, $mode);
    }
}
