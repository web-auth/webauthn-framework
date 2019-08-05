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

class MetadataStatementRepository
{
    /**
     * @var MetadataService[]
     */
    private $services = [];

    /**
     * @var SingleMetadata[]
     */
    private $singleStatements = [];

    public function addService(MetadataService $service): void
    {
        $this->services[] = $service;
    }

    public function addSingleStatement(SingleMetadata $singleStatements): void
    {
        $this->singleStatements[] = $singleStatements;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        foreach ($this->services as $service) {
            try {
                $tableOfContent = $service->getMetadataTOCPayload();
                $entries = $tableOfContent->getEntries();
                foreach ($entries as $entry) {
                    try {
                        $metadataStatement = $service->getMetadataStatementFor($entry);
                        if ($metadataStatement->getAaguid() === $aaguid) {
                            return $metadataStatement;
                        }
                    } catch (\Throwable $throwable) {
                        continue;
                    }
                }
            } catch (\Throwable $throwable) {
                continue;
            }
        }

        foreach ($this->singleStatements as $singleStatement) {
            try {
                $metadataStatement = $singleStatement->getMetadataStatement();
                if ($metadataStatement->getAaguid() === $aaguid) {
                    return $metadataStatement;
                }
            } catch (\Throwable $throwable) {
                continue;
            }
        }

        return null;
    }

    /**
     * @return MetadataService[]
     */
    protected function getServices(): array
    {
        return $this->services;
    }

    /**
     * @return SingleMetadata[]
     */
    protected function getSingleStatements(): array
    {
        return $this->singleStatements;
    }
}
