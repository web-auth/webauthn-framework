<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use JsonSerializable;

class AuthenticationExtension implements JsonSerializable
{
    public function __construct(
        private readonly string $name,
        private readonly mixed $value
    ) {
    }

    public static function create(string $name, mixed $value): self
    {
        return new self($name, $value);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function value(): mixed
    {
        return $this->value;
    }

    public function jsonSerialize(): mixed
    {
        return $this->value;
    }
}
