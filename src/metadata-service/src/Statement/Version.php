<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\ValueFilter;

class Version implements JsonSerializable
{
    use ValueFilter;

    public function __construct(
        public readonly ?int $major,
        public readonly ?int $minor
    ) {
        if ($major === null && $minor === null) {
            throw MetadataStatementLoadingException::create('Invalid data. Must contain at least one item');
        }
        $major >= 0 || throw MetadataStatementLoadingException::create('Invalid argument "major"');
        $minor >= 0 || throw MetadataStatementLoadingException::create('Invalid argument "minor"');
    }

    public static function create(?int $major, ?int $minor): self
    {
        return new self($major, $minor);
    }

    /**
     * @return array<string, int|null>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'major' => $this->major,
            'minor' => $this->minor,
        ];

        return self::filterNullValues($data);
    }
}
