<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use function array_key_exists;
use Assert\Assertion;
use JsonSerializable;

class MetadataTOCPayload implements JsonSerializable
{
    /**
     * @var MetadataTOCPayloadEntry[]
     */
    private array $entries = [];

    /**
     * @var string[]
     */
    private array $rootCertificates;

    public function __construct(
        private int $no,
        private string $nextUpdate,
        private ?string $legalHeader = null
    ) {
    }

    public function addEntry(MetadataTOCPayloadEntry $entry): self
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
     * @return MetadataTOCPayloadEntry[]
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach (['no', 'nextUpdate', 'entries'] as $key) {
            Assertion::keyExists(
                $data,
                $key,
                Utils::logicException(sprintf('Invalid data. The parameter "%s" is missing', $key))
            );
        }
        Assertion::integer($data['no'], Utils::logicException('Invalid data. The parameter "no" shall be an integer'));
        Assertion::string(
            $data['nextUpdate'],
            Utils::logicException('Invalid data. The parameter "nextUpdate" shall be a string')
        );
        Assertion::isArray(
            $data['entries'],
            Utils::logicException('Invalid data. The parameter "entries" shall be a n array of entries')
        );
        if (array_key_exists('legalHeader', $data)) {
            Assertion::string(
                $data['legalHeader'],
                Utils::logicException('Invalid data. The parameter "legalHeader" shall be a string')
            );
        }
        $object = new self($data['no'], $data['nextUpdate'], $data['legalHeader'] ?? null);
        foreach ($data['entries'] as $entry) {
            $object->addEntry(MetadataTOCPayloadEntry::createFromArray($entry));
        }
        $object->rootCertificates = $data['rootCertificates'] ?? [];

        return $object;
    }

    public function jsonSerialize(): array
    {
        $data = [
            'legalHeader' => $this->legalHeader,
            'nextUpdate' => $this->nextUpdate,
            'no' => $this->no,
            'entries' => array_map(static function (MetadataTOCPayloadEntry $object): array {
                return $object->jsonSerialize();
            }, $this->entries),
            'rootCertificates' => $this->rootCertificates,
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
