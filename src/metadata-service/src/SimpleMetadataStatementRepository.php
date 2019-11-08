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
use Throwable;

class SimpleMetadataStatementRepository implements MetadataStatementStatusReportRepository
{
    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    /**
     * @var MetadataService[]
     */
    private $services = [];

    /**
     * @var SingleMetadata[]
     */
    private $singleStatements = [];

    public function __construct(CacheItemPoolInterface $cacheItemPool)
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    public function addService(string $name, MetadataService $service): self
    {
        $this->services[$name] = $service;

        return $this;
    }

    public function addSingleStatement(string $name, SingleMetadata $singleStatements): self
    {
        $this->singleStatements[$name] = $singleStatements;

        return $this;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        $metadataStatement = $this->findOneByAAGUIDFromServices($aaguid);
        if (null !== $metadataStatement) {
            return $metadataStatement;
        }

        return $this->findOneByAAGUIDFromSingleStatements($aaguid);
    }

    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        $entry = $this->findEntryForAAGUID($aaguid);

        return null === $entry ? [] : $entry->getStatusReports();
    }

    private function findOneByAAGUIDFromSingleStatements(string $aaguid): ?MetadataStatement
    {
        foreach ($this->singleStatements as $name => $singleStatement) {
            try {
                $singleCacheItem = $this->cacheItemPool->getItem(sprintf('MDS-%s', $name));
                if (!$singleCacheItem->isHit()) {
                    $metadataStatement = $singleStatement->getMetadataStatement();
                    $singleCacheItem->set($metadataStatement);
                    $this->cacheItemPool->save($singleCacheItem);
                } else {
                    $metadataStatement = $singleCacheItem->get();
                }

                if ($metadataStatement->getAaguid() === $aaguid) {
                    return $metadataStatement;
                }
            } catch (Throwable $throwable) {
                continue;
            }
        }

        return null;
    }

    private function findOneByAAGUIDFromServices(string $aaguid): ?MetadataStatement
    {
        $entry = $this->findEntryForAAGUID($aaguid, $service);
        try {
            return $service->getMetadataStatementFor($entry);
        } catch (Throwable $throwable) {
            return null;
        }
    }

    private function findEntryForAAGUID(string $aaguid, ?MetadataService &$service = null): ?MetadataTOCPayloadEntry
    {
        foreach ($this->services as $name => $s) {
            try {
                $tableOfContent = $s->getMetadataTOCPayload();
                foreach ($tableOfContent->getEntries() as $entry) {
                    if ($aaguid !== $entry->getAaguid()) { //Does not correspond
                        continue;
                    }
                    if (null === $entry->getUrl() || null === $entry->getHash()) { //Not published
                        continue;
                    }
                    $service = $s;

                    return $entry;
                }
            } catch (Throwable $throwable) {
                continue;
            }
        }

        return null;
    }
}
