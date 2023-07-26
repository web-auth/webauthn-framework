<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\Uvm;

use Webauthn\AuthenticationExtensions\ExtensionInput;

final class UvmExtensionInput implements ExtensionInput
{
    private function __construct(
        private readonly bool $requested
    ) {
    }

    public static function create(bool $requested): self
    {
        return new self($requested);
    }

    public static function requested(): self
    {
        return new self(true);
    }

    public static function notRequested(): self
    {
        return new self(false);
    }

    public function indentifier(): string
    {
        return 'uvm';
    }

    public function jsonSerialize(): bool
    {
        return $this->requested;
    }

    public function identifier(): string
    {
        return 'uvm';
    }
}
