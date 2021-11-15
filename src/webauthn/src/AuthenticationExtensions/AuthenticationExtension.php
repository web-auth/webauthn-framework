<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use JsonSerializable;

class AuthenticationExtension implements JsonSerializable
{
    public function __construct(
        private string $name,
        private mixed $value
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

    public function value()
    {
        return $this->value;
    }

    public function jsonSerialize()
    {
        return $this->value;
    }
}
