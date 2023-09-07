<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;
use function is_array;
use function is_int;
use function is_string;

/**
 * @final
 */
class MetadataBLOBPayload implements JsonSerializable
{
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
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addEntry(MetadataBLOBPayloadEntry $entry): self
    {
        $this->entries[] = $entry;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getLegalHeader(): ?string
    {
        return $this->legalHeader;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getNo(): int
    {
        return $this->no;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getNextUpdate(): string
    {
        return $this->nextUpdate;
    }

    /**
     * @return MetadataBLOBPayloadEntry[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['no', 'nextUpdate', 'entries'] as $key) {
            array_key_exists($key, $data) || throw MetadataStatementLoadingException::create(sprintf(
                'Invalid data. The parameter "%s" is missing',
                $key
            ));
        }
        is_int($data['no']) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "no" shall be an integer'
        );
        is_string($data['nextUpdate']) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "nextUpdate" shall be a string'
        );
        is_array($data['entries']) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "entries" shall be a n array of entries'
        );
        $object = new self($data['no'], $data['nextUpdate'], $data['legalHeader'] ?? null);
        foreach ($data['entries'] as $entry) {
            $object->entries[] = MetadataBLOBPayloadEntry::createFromArray($entry);
        }

        return $object;
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
            'entries' => array_map(
                static fn (MetadataBLOBPayloadEntry $object): array => $object->jsonSerialize(),
                $this->entries
            ),
        ];

        return Utils::filterNullValues($data);
    }

    /**
     * @return string[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRootCertificates(): array
    {
        return $this->rootCertificates;
    }

    /**
     * @param string[] $rootCertificates
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function setRootCertificates(array $rootCertificates): self
    {
        $this->rootCertificates = $rootCertificates;

        return $this;
    }
}
