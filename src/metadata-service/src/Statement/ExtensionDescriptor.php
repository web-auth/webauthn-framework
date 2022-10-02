<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class ExtensionDescriptor implements JsonSerializable
{
    private readonly ?int $tag;

    public function __construct(
        private readonly string $id,
        ?int $tag,
        private readonly ?string $data,
        private readonly bool $failIfUnknown
    ) {
        if ($tag !== null) {
            $tag >= 0 || throw MetadataStatementLoadingException::create(
                'Invalid data. The parameter "tag" shall be a positive integer'
            );
        }
        $this->tag = $tag;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getTag(): ?int
    {
        return $this->tag;
    }

    public function getData(): ?string
    {
        return $this->data;
    }

    public function isFailIfUnknown(): bool
    {
        return $this->failIfUnknown;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        array_key_exists('id', $data) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "id" is missing'
        );
        array_key_exists('fail_if_unknown', $data) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "fail_if_unknown" is missing'
        );

        return new self($data['id'], $data['tag'] ?? null, $data['data'] ?? null, $data['fail_if_unknown']);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $result = [
            'id' => $this->id,
            'tag' => $this->tag,
            'data' => $this->data,
            'fail_if_unknown' => $this->failIfUnknown,
        ];

        return Utils::filterNullValues($result);
    }
}
