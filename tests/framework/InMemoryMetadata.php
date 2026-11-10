<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use Webauthn\MetadataService\MetadataStatementRepository;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\StatusReportRepository;

final readonly class InMemoryMetadata implements MetadataStatementRepository, StatusReportRepository
{
    /**
     * @param array<string, MetadataStatement> $statements
     * @param array<string, StatusReport[]> $statusReports
     */
    public function __construct(
        private array $statements = [],
        private array $statusReports = [],
    ) {
    }

    public function findOneByAAGUID(string $aaguid): ?MetadataStatement
    {
        return $this->statements[$aaguid] ?? null;
    }

    public function findStatusReportsByAAGUID(string $aaguid): array
    {
        return $this->statusReports[$aaguid] ?? [];
    }

    /**
     * @param string[] $attestationRootCertificates
     * @param string[] $attestationTypes
     */
    public static function statement(
        string $aaguid,
        array $attestationRootCertificates,
        array $attestationTypes = [MetadataStatement::ATTESTATION_BASIC_FULL],
    ): MetadataStatement {
        return MetadataStatement::create(
            description: 'Authenticator ' . $aaguid,
            authenticatorVersion: 1,
            protocolFamily: 'fido2',
            schema: 3,
            upv: [],
            authenticationAlgorithms: [],
            publicKeyAlgAndEncodings: [],
            attestationTypes: $attestationTypes,
            userVerificationDetails: null,
            matcherProtection: [],
            tcDisplay: [],
            attestationRootCertificates: $attestationRootCertificates,
            aaguid: $aaguid,
        );
    }

    public static function statusReport(string $status): StatusReport
    {
        return StatusReport::create($status, null, null, null, null, null, null, null);
    }
}
