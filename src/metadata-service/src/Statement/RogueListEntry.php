<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use function array_key_exists;
use function is_string;

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
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getSk(): string
    {
        return $this->sk;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
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

        return self::create($data['sk'], $data['date']);
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
