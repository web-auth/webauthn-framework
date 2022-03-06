<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Throwable;
use Webauthn\AttestationStatement\CanSupportStatusReport;
use Webauthn\MetadataService\MetadataService;
use Webauthn\MetadataService\MetadataStatement;
use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\SingleMetadata;
use Webauthn\MetadataService\StatusReport;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface, CanSupportStatusReport
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

    public function addSingleStatement(SingleMetadata ...$statements): void
    {
        foreach ($statements as $statement) {
            $this->metadataStatements[] = $statement;
        }
    }

    public function addServices(MetadataService ...$services): void
    {
        foreach ($services as $service) {
            $this->metadataServices[] = $service;
        }
    }

    public function addStatusReport(string $aaguid, StatusReport $statusReport): void
    {
        if (! isset($this->statusReports[$aaguid])) {
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

    /**
     * {@inheritdoc}
     */
    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return $this->statusReports[$aaguid] ?? [];
    }
}
