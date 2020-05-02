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

namespace Webauthn\Bundle\Tests\Functional;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Webauthn\MetadataService\DistantSingleMetadata;
use Webauthn\MetadataService\MetadataService;
use Webauthn\MetadataService\MetadataStatement;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\SingleMetadata;
use Webauthn\MetadataService\StatusReport;

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

    /**
     * @var StatusReport[][]
     */
    private $statusReports = [];

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    public function __construct(ClientInterface $httpClient, RequestFactoryInterface $requestFactory)
    {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
    }

    public function addSingleStatement(string $data, bool $isBare64Encoded = false): void
    {
        $this->metadataStatements[] = new SingleMetadata($data, $isBare64Encoded);
    }

    public function addDistantSingleStatement(string $uri, bool $isBare64Encoded = false, array $additionalHeaders = []): void
    {
        $this->metadataStatements[] = new DistantSingleMetadata($uri, $isBare64Encoded, $this->httpClient, $this->requestFactory, $additionalHeaders);
    }

    public function addService(string $url, array $additionalQueryStringParameters = [], array $additionalHeaders = []): void
    {
        $this->metadataServices[] = new MetadataService($url, $this->httpClient, $this->requestFactory, $additionalQueryStringParameters, $additionalHeaders);
    }

    public function addStatusReport(string $aaguid, StatusReport $statusReport): void
    {
        if (!isset($this->statusReports[$aaguid])) {
            $this->statusReports[$aaguid] = [];
        }
        $this->statusReports[$aaguid][] = $statusReport;
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        foreach ($this->metadataStatements as $metadataStatement) {
            try {
                $mds = $metadataStatement->getMetadataStatement();
                if ($mds->getAaguid() === $aaguid) {
                    return $mds;
                }
            } catch (\Throwable $throwable) {
                continue;
            }
        }
        foreach ($this->metadataServices as $metadataService) {
            try {
                $toc = $metadataService->getMetadataTOCPayload();
                foreach ($toc->getEntries() as $entry) {
                    if ($entry->getAaguid() === $aaguid) {
                        try {
                            return $metadataService->getMetadataStatementFor($entry);
                        } catch (\Throwable $throwable) {
                            continue;
                        }
                    }
                }
            } catch (\Throwable $throwable) {
                continue;
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
