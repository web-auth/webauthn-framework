<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use JsonSerializable;

class AlternativeDescriptions implements JsonSerializable
{
    /**
     * @var array<string, string>
     */
    private array $descriptions = [];

    /**
     * @param array<string, string> $descriptions
     */
    public static function create(array $descriptions = []): self
    {
        $object = new self();
        foreach ($descriptions as $k => $v) {
            $object->add($k, $v);
        }

        return $object;
    }

    public function add(string $locale, string $description): self
    {
        $this->descriptions[$locale] = $description;

        return $this;
    }

    public function jsonSerialize(): array
    {
        return $this->descriptions;
    }
}
