<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;

class RogueListEntry implements JsonSerializable
{
    #[Pure]
    public function __construct(private string $sk, private string $date)
    {
    }

    #[Pure]
    public function getSk(): string
    {
        return $this->sk;
    }

    #[Pure]
    public function getDate(): ?string
    {
        return $this->date;
    }

    public static function createFromArray(array $data): self
    {
        Assertion::keyExists($data, 'sk', 'The key "sk" is missing');
        Assertion::string($data['sk'], 'The key "sk" is invalid');
        Assertion::keyExists($data, 'date', 'The key "date" is missing');
        Assertion::string($data['date'], 'The key "date" is invalid');

        return new self(
            $data['sk'],
            $data['date']
        );
    }

    #[Pure]
    #[ArrayShape(['sk' => 'string', 'date' => 'string'])]
    public function jsonSerialize(): array
    {
        return [
            'sk' => $this->sk,
            'date' => $this->date,
        ];
    }
}
