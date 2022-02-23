<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

class AlternativeDescriptions implements JsonSerializable
{
    /**
     * @var array<string, string>
     */
    private array $descriptions =  [];

    public static function create(): self
    {
        return new self();
    }

    public function add(string $locale, string $description): self
    {
        $this->descriptions[$locale] = $description;

        return $this;
    }

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        return $this->descriptions;
    }
}
