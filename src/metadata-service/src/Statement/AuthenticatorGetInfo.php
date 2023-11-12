<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

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
     * @param array<string|int, mixed> $info
     */
    public static function create(array $info = []): self
    {
        return new self($info);
    }

    /**
     * @deprecated since 4.7.0. Please use the constructor directly.
     * @infection-ignore-all
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
