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

use Psr\Cache\CacheItemPoolInterface;

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

    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

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
            $tableOfContent = $service->getMetadataTOCPayload();
            $entries = $tableOfContent->getEntries();
            foreach ($entries as $entry) {
                $metadataStatement = $service->getMetadataStatementFor($entry);
                if ($metadataStatement->getAaguid() === $aaguid) {
                    return $metadataStatement;
                }
            }
        }

        foreach ($this->singleStatements as $singleStatement) {
            $metadataStatement = $singleStatement->getMetadataStatement();
            if ($metadataStatement->getAaguid() === $aaguid) {
                return $metadataStatement;
            }
        }

        return null;
    }

    public function findOneByAAID(string $aaid): ?MetadataStatement
    {
        foreach ($this->services as $service) {
            $tableOfContent = $service->getMetadataTOCPayload();
            $entries = $tableOfContent->getEntries();
            foreach ($entries as $entry) {
                $metadataStatement = $service->getMetadataStatementFor($entry);
                if ($metadataStatement->getAaid() === $aaid) {
                    return $metadataStatement;
                }
            }
        }

        foreach ($this->singleStatements as $singleStatement) {
            $metadataStatement = $singleStatement->getMetadataStatement();
            if ($metadataStatement->getAaguid() === $aaid) {
                return $metadataStatement;
            }
        }

        return null;
    }

    /**
     * @return MetadataStatement[]
     */
    public function findAll(): array
    {
        $result = [];
        foreach ($this->services as $service) {
            $tableOfContent = $service->getMetadataTOCPayload();
            foreach ($tableOfContent->getEntries() as $entry) {
                $result[] = $service->getMetadataStatementFor($entry);
            }
        }

        foreach ($this->singleStatements as $singleStatement) {
            $result[] = $singleStatement->getMetadataStatement();
        }

        return $result;
    }
}
