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
 * @implements IteratorAggregate<ExtensionInput>
 */
final class ExtensionInputs implements JsonSerializable, Countable, IteratorAggregate
{
    /**
     * @var array<string, ExtensionInput>
     */
    private array $extensions = [];

    public static function create(): self
    {
        return new self();
    }

    public function add(ExtensionInput ...$extensions): void
    {
        foreach ($extensions as $extension) {
            $this->extensions[$extension->identifier()] = $extension;
        }
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->extensions);
    }

    public function get(string $key): ExtensionInput
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
        return $this->extensions;
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
