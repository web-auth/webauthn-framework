<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Functional;

use Webauthn\MetadataService\MetadataStatementInterface;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\Object\MetadataService;
use Webauthn\MetadataService\Object\SingleMetadata;
use Webauthn\MetadataService\Object\StatusReport;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface
{
    /**
     * @var SingleMetadata[]
     */
    private $distantMetadataStatements = [];

    /**
     * @var MetadataService[]
     */
    private $metadataServices = [];

    /**
     * @var StatusReport[][]
     */
    private $statusReports = [];

    public function addSingleStatement(SingleMetadata $metadataStatement): void
    {
        $this->distantMetadataStatements[] = $metadataStatement;
    }

    public function addService(MetadataService $metadataService): void
    {
        $this->metadataServices[] = $metadataService;
    }

    public function addStatusReport(string $aaguid, StatusReport $statusReport): void
    {
        if (!isset($this->statusReports[$aaguid])) {
            $this->statusReports[$aaguid] = [];
        }
        $this->statusReports[$aaguid][] = $statusReport;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatementInterface
    {
        foreach ($this->distantMetadataStatements as $distantMetadataStatement) {
            if ($distantMetadataStatement->getMetadataStatement()->getAaguid() === $aaguid) {
                return $distantMetadataStatement->getMetadataStatement();
            }
        }
        foreach ($this->metadataServices as $metadataService) {
            $toc = $metadataService->getMetadataTOCPayload();
            foreach ($toc->getEntries() as $entry) {
                if ($entry->getAaguid() === $aaguid) {
                    return $metadataService->getMetadataStatementFor($entry);
                }
            }
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return $this->statusReports[$aaguid] ?? [];
    }
}
