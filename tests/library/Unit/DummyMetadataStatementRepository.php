<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Service\MetadataBLOBPayloadEntry;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;

/**
 * @internal
 */
final class DummyMetadataStatementRepository implements MetadataStatementRepository, StatusReportRepository
{
    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        if ($aaguid !== '08987058-cadc-4b81-b6e1-30de50dcbe96') {
            return null;
        }

        return $this->loadWindowsHelloMDS()
            ->getMetadataStatement();
    }

    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        if ($aaguid !== '08987058-cadc-4b81-b6e1-30de50dcbe96') {
            return [];
        }

        return $this->loadWindowsHelloMDS()
            ->getStatusReports();
    }

    private function loadWindowsHelloMDS(): MetadataBLOBPayloadEntry
    {
        $data = file_get_contents(__DIR__ . '/../../windows-hello.json');

        return MetadataBLOBPayloadEntry::createFromArray(json_decode($data, true, 512, JSON_THROW_ON_ERROR));
    }
}
