<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Webauthn\MetadataService\Statement\MetadataStatement;

interface CanSupportImport
{
    public function import(MetadataStatement $metadataStatement): void;
}
