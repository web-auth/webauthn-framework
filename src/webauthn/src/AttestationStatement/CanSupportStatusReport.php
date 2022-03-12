<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use Webauthn\MetadataService\StatusReport;

interface CanSupportStatusReport
{
    /**
     * @return StatusReport[]
     */
    public function findStatusReportsByAAGUID(string $aaguid): array;
}
