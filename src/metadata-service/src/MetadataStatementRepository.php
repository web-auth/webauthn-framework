<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

interface MetadataStatementRepository
{
    public function findOneByAAGUID(string $aaguid): ?MetadataStatement;
}
