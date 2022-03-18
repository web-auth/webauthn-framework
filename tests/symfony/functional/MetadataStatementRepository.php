<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Webauthn\MetadataService\MetadataStatementRepository as MetadataStatementRepositoryInterface;
use Webauthn\MetadataService\Service\MetadataService;
use Webauthn\MetadataService\Statement\MetadataStatement;

final class MetadataStatementRepository implements MetadataStatementRepositoryInterface
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
}
