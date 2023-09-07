<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

/**
 * @final
 */
class AuthenticatorGetInfo implements JsonSerializable
{
    /**
     * @param array<string|int, mixed> $info
     */
    public function __construct(
        public array $info = []
    ) {
    }

    /**
     * @param array<string|int, mixed> $data
     */
    public static function create(array $data = []): self
    {
        return new self($data);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function add(string|int $key, mixed $value): self
    {
        $this->info[$key] = $value;

        return $this;
    }

    /**
     * @return string[]
     */
    public function jsonSerialize(): array
    {
        return $this->info;
    }
}
