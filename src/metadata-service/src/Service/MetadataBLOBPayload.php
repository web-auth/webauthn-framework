<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use function array_key_exists;
use function is_array;
use function is_int;
use function is_string;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class MetadataBLOBPayload implements JsonSerializable
{
    /**
     * @var MetadataBLOBPayloadEntry[]
     */
    private array $entries = [];

    /**
     * @var string[]
     */
    private array $rootCertificates = [];

    public function __construct(
        private readonly int $no,
        private readonly string $nextUpdate,
        private readonly ?string $legalHeader = null
    ) {
    }

    public function addEntry(MetadataBLOBPayloadEntry $entry): self
    {
        $this->entries[] = $entry;

        return $this;
    }

    public function getLegalHeader(): ?string
    {
        return $this->legalHeader;
    }

    public function getNo(): int
    {
        return $this->no;
    }

    public function getNextUpdate(): string
    {
        return $this->nextUpdate;
    }

    /**
     * @return MetadataBLOBPayloadEntry[]
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
            $object->addEntry(MetadataBLOBPayloadEntry::createFromArray($entry));
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
     */
    public function getRootCertificates(): array
    {
        return $this->rootCertificates;
    }

    /**
     * @param string[] $rootCertificates
     */
    public function setRootCertificates(array $rootCertificates): self
    {
        $this->rootCertificates = $rootCertificates;

        return $this;
    }
}
