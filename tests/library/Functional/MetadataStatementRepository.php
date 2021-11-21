<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Functional;

use Webauthn\MetadataService\MetadataService;
use Webauthn\MetadataService\MetadataStatement;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\SingleMetadata;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface
{
    /**
     * @var SingleMetadata[]
     */
    private $metadataStatements = [];

    /**
     * @var MetadataService[]
     */
    private $metadataServices = [];

    public function addSingleStatement(SingleMetadata $metadataStatement): void
    {
        $this->metadataStatements[] = $metadataStatement;
    }

    public function addService(MetadataService $metadataService): void
    {
        $this->metadataServices[] = $metadataService;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        foreach ($this->metadataStatements as $metadataStatement) {
            if ($metadataStatement->getMetadataStatement()->getAaguid() === $aaguid) {
                return $metadataStatement->getMetadataStatement();
            }
        }
        foreach ($this->metadataServices as $metadataService) {
            if ($metadataService->has($aaguid)) {
                return $metadataService->get($aaguid);
            }
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return [];
    }
}
