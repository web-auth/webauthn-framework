<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\ValueFilter;

class ExtensionDescriptor implements JsonSerializable
{
    use ValueFilter;

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

        return self::filterNullValues($result);
    }
}
