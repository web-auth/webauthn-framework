<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

class RogueListEntry implements JsonSerializable
{
    public function __construct(
        public readonly string $sk,
        public readonly string $date
    ) {
    }

    public static function create(string $sk, string $date): self
    {
        return new self($sk, $date);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'sk' => $this->sk,
            'date' => $this->date,
        ];
    }
}
