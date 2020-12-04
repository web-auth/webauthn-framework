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
use Webauthn\MetadataService\StatusReportInterface;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface
{
    /**
     * @var array<string, array<int, StatusReportInterface>>
     */
    private $statusReports = [];

    /**
     * @var array<string, MetadataStatementInterface>
     */
    private $metadataStatements;

    public function add(MetadataStatementInterface $metadataStatement): self
    {
        $this->metadataStatements[$metadataStatement->getAaguid()] = $metadataStatement;

        return $this;
    }

    public function addStatusReport(string $aaguid, StatusReportInterface $statusReport): self
    {
        if (!isset($this->statusReports[$aaguid])) {
            $this->statusReports[$aaguid] = [];
        }
        $this->statusReports[$aaguid][] = $statusReport;

        return $this;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatementInterface
    {
        return $this->metadataStatements[$aaguid] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return $this->statusReports[$aaguid] ?? [];
    }
}
