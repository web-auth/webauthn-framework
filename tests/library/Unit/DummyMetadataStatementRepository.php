<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\MetadataService\Denormalizer\MetadataStatementSerializerFactory;
use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Service\MetadataBLOBPayloadEntry;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\StatusReportRepository;

/**
 * @internal
 */
final class DummyMetadataStatementRepository implements MetadataStatementRepository, StatusReportRepository
{
    private readonly SerializerInterface $serializer;

    public function __construct()
    {
        $this->serializer = MetadataStatementSerializerFactory::create();
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        if ($aaguid !== '08987058-cadc-4b81-b6e1-30de50dcbe96') {
            return null;
        }

        return $this->loadWindowsHelloMDS()
            ->metadataStatement;
    }

    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        if ($aaguid !== '08987058-cadc-4b81-b6e1-30de50dcbe96') {
            return [];
        }

        return $this->loadWindowsHelloMDS()
            ->statusReports;
    }

    private function loadWindowsHelloMDS(): MetadataBLOBPayloadEntry
    {
        $data = file_get_contents(__DIR__ . '/../../windows-hello.json');

        return $this->serializer->deserialize($data, MetadataBLOBPayloadEntry::class, 'json');
    }
}
