<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

class AlternativeDescriptions implements JsonSerializable
{
    /**
     * @param array<string, string> $descriptions
     */
    public function __construct(
        public array $descriptions = []
    ) {
    }

    /**
     * @param array<string, string> $descriptions
     */
    public static function create(array $descriptions = []): self
    {
        return new self($descriptions);
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->descriptions;
    }
}
