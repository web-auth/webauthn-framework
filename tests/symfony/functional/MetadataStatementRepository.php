<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\Service\MetadataService;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository as StatusReportRepositoryInterface;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface, StatusReportRepositoryInterface
{
    public function __construct(
        private MetadataService $service
    ) {
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        if (! $this->service->has($aaguid)) {
            return null;
        }

        return $this->service->get($aaguid);
    }

    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return [];
    }
}
