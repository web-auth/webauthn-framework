<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;
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
    private array $metadataStatements = [];

    /**
     * @var MetadataService[]
     */
    private array $metadataServices = [];

    /**
     * @var StatusReport[][]
     */
    private array $statusReports = [];

    public function __construct(private ClientInterface $httpClient, private RequestFactoryInterface $requestFactory)
    {
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
        $service = new MetadataService($url, $this->httpClient, $this->requestFactory);
        $service
            ->addQueryStringValues($additionalQueryStringParameters)
            ->addHeaders($additionalHeaders)
        ;

        $this->metadataServices[] = $service;
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
            } catch (Throwable) {
                continue;
            }
        }
        foreach ($this->metadataServices as $metadataService) {
            try {
                if ($metadataService->has($aaguid)) {
                    return $metadataService->get($aaguid);
                }
            } catch (Throwable) {
                continue;
            }
        }

        return null;
    }
}
