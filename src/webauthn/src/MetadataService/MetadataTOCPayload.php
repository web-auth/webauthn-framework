<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

class MetadataTOCPayload implements \JsonSerializable
{
    /**
     * @var string|null
     */
    private $legalHeader;

    /**
     * @var int
     */
    private $no;

    /**
     * @var string
     */
    private $nextUpdate;

    /**
     * @var MetadataTOCPayloadEntry[]
     */
    private $entries;

    public function getLegalHeader(): ?string
    {
        return $this->legalHeader;
    }

    public function setLegalHeader(?string $legalHeader): void
    {
        $this->legalHeader = $legalHeader;
    }

    public function getNo(): int
    {
        return $this->no;
    }

    public function setNo(int $no): void
    {
        $this->no = $no;
    }

    public function getNextUpdate(): string
    {
        return $this->nextUpdate;
    }

    public function setNextUpdate(string $nextUpdate): void
    {
        $this->nextUpdate = $nextUpdate;
    }

    /**
     * @return MetadataTOCPayloadEntry[]
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    public function addEntry(MetadataTOCPayloadEntry $entry): void
    {
        $this->entries[] = $entry;
    }

    public function jsonSerialize(): array
    {
        return [
        ];
    }
}
