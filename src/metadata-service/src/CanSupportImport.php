<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

interface CanSupportImport
{
    public function import(MetadataStatement $metadataStatement): void;
}
