<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;

/**
 * @final
 */
class ExtensionDescriptor implements JsonSerializable
{
    public function __construct(
        public readonly string $id,
        public readonly ?int $tag,
        public readonly ?string $data,
        public readonly bool $failIfUnknown
    ) {
        if ($tag !== null) {
            $tag >= 0 || throw MetadataStatementLoadingException::create(
                'Invalid data. The parameter "tag" shall be a positive integer'
            );
        }
    }

    public static function create(
        string $id,
        ?int $tag = null,
        ?string $data = null,
        bool $failIfUnknown = false
    ): self {
        return new self($id, $tag, $data, $failIfUnknown);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getTag(): ?int
    {
        return $this->tag;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getData(): ?string
    {
        return $this->data;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
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
