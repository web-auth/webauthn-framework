<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

/**
 * @final
 */
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

    /**
     * @return array<string, string>
     */
    public function all(): array
    {
        return $this->descriptions;
    }

    public function add(string $locale, string $description): self
    {
        $this->descriptions[$locale] = $description;

        return $this;
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->descriptions;
    }
}
