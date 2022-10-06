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
use JsonSerializable;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @implements IteratorAggregate<AuthenticationExtension>
 */
class AuthenticationExtensionsClientInputs implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var AuthenticationExtension[]
     */
    private array $extensions = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(AuthenticationExtension ...$extensions): self
    {
        foreach ($extensions as $extension) {
            $this->extensions[$extension->name()] = $extension;
        }

        return $this;
    }

    /**
     * @param array<string, mixed> $json
     */
    public static function createFromArray(array $json): self
    {
        $object = new self();
        foreach ($json as $k => $v) {
            $object->add(AuthenticationExtension::create($k, $v));
        }

        return $object;
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
