<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use Webauthn\MetadataService\StatusReportRepository as StatusReportRepositoryInterface;

final class StatusReportRepository implements StatusReportRepositoryInterface
{
    public function findStatusReportsByAAGUID(string $aaguid): iterable
    {
        return [];
    }
}
