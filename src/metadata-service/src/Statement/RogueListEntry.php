<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use function is_string;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;

/**
 * @final
 */
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
        array_key_exists('sk', $data) || throw MetadataStatementLoadingException::create('The key "sk" is missing');
        is_string($data['sk']) || throw MetadataStatementLoadingException::create('The key "date" is invalid');
        array_key_exists('date', $data) || throw MetadataStatementLoadingException::create(
            'The key "date" is missing'
        );
        is_string($data['date']) || throw MetadataStatementLoadingException::create('The key "date" is invalid');

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
