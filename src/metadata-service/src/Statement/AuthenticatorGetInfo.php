<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

class AuthenticatorGetInfo implements JsonSerializable
{
    /**
     * @param array<array-key, mixed> $info
     */
    public function __construct(
        public array $info = []
    ) {
    }

    /**
     * @param array<array-key, mixed> $info
     */
    public static function create(array $info = []): self
    {
        return new self($info);
    }

    /**
     * @return array<array-key, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->info;
    }
}
