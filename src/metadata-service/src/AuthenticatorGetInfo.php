<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

class AuthenticatorGetInfo implements JsonSerializable
{
    /**
     * @var string[]
     */
    private array $info =  [];

    public static function create(): self
    {
        return new self();
    }

    public function add(string $description): self
    {
        $this->info[] = $description;

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
