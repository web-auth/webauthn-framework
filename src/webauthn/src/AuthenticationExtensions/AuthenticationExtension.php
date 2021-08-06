<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use JetBrains\PhpStorm\Pure;
use JsonSerializable;

class AuthenticationExtension implements JsonSerializable
{
    #[Pure]
    public function __construct(private string $name, private mixed $value)
    {
    }

    #[Pure]
    public static function create(string $name, mixed $value): self
    {
        return new self($name, $value);
    }

    #[Pure]
    public function name(): string
    {
        return $this->name;
    }

    #[Pure]
    public function value(): mixed
    {
        return $this->value;
    }

    #[Pure]
    public function jsonSerialize(): mixed
    {
        return $this->value;
    }
}
