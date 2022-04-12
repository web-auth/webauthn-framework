<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use JsonSerializable;

class RogueListEntry implements JsonSerializable
{
    public function __construct(
        private readonly string $sk,
        private readonly string $date
    ) {
    }

    public function getSk(): string
    {
        return $this->sk;
    }

    public function getDate(): ?string
    {
        return $this->date;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        Assertion::keyExists($data, 'sk', 'The key "sk" is missing');
        Assertion::string($data['sk'], 'The key "sk" is invalid');
        Assertion::keyExists($data, 'date', 'The key "date" is missing');
        Assertion::string($data['date'], 'The key "date" is invalid');

        return new self($data['sk'], $data['date']);
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
