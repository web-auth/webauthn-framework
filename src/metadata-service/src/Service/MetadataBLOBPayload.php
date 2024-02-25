<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use JsonSerializable;
use Webauthn\MetadataService\ValueFilter;

class MetadataBLOBPayload implements JsonSerializable
{
    use ValueFilter;

    /**
     * @var string[]
     */
    private array $rootCertificates = [];

    /**
     * @param MetadataBLOBPayloadEntry[] $entries
     */
    public function __construct(
        public readonly int $no,
        public readonly string $nextUpdate,
        public readonly ?string $legalHeader = null,
        public array $entries = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'legalHeader' => $this->legalHeader,
            'nextUpdate' => $this->nextUpdate,
            'no' => $this->no,
            'entries' => $this->entries,
        ];

        return self::filterNullValues($data);
    }
}
