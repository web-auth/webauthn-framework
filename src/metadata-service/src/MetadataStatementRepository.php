<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

interface MetadataStatementRepository
{
    public function findOneByAAGUID(string $aaguid): ?MetadataStatement;

    /**
     * @deprecated This method is deprecated since v3.3 and will be removed in v4.0. Please use the method "getStatusReports()" provided by the MetadataStatement object
     *
     * @return StatusReport[]
     */
    public function findStatusReportsByAAGUID(string $aaguid): array;
}
