<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\BiometricStatusReport;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\ValueFilter;
use function count;
use function is_string;

class MetadataBLOBPayloadEntry implements JsonSerializable
{
    use ValueFilter;

    /**
     * @param StatusReport[] $statusReports
     * @param BiometricStatusReport[] $biometricStatusReports
     * @param string[] $attestationCertificateKeyIdentifiers
     */
    public function __construct(
        public readonly string $timeOfLastStatusChange,
        public array $statusReports,
        public readonly ?string $aaid = null,
        public readonly ?string $aaguid = null,
        public array $attestationCertificateKeyIdentifiers = [],
        public readonly ?MetadataStatement $metadataStatement = null,
        public readonly ?string $rogueListURL = null,
        public readonly ?string $rogueListHash = null,
        public array $biometricStatusReports = []
    ) {
        if ($aaid !== null && $aaguid !== null) {
            throw MetadataStatementLoadingException::create('Authenticators cannot support both AAID and AAGUID');
        }
        if ($aaid === null && $aaguid === null && count($attestationCertificateKeyIdentifiers) === 0) {
            throw MetadataStatementLoadingException::create(
                'If neither AAID nor AAGUID are set, the attestation certificate identifier list shall not be empty'
            );
        }
        foreach ($attestationCertificateKeyIdentifiers as $attestationCertificateKeyIdentifier) {
            is_string($attestationCertificateKeyIdentifier) || throw MetadataStatementLoadingException::create(
                'Invalid attestation certificate identifier. Shall be a list of strings'
            );
            preg_match(
                '/^[0-9a-f]+$/',
                $attestationCertificateKeyIdentifier
            ) === 1 || throw MetadataStatementLoadingException::create(
                'Invalid attestation certificate identifier. Shall be a list of strings'
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'statusReports' => $this->statusReports,
            'timeOfLastStatusChange' => $this->timeOfLastStatusChange,
            'rogueListURL' => $this->rogueListURL,
            'rogueListHash' => $this->rogueListHash,
        ];

        return self::filterNullValues($data);
    }
}
