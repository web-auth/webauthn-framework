<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Service;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\BiometricStatusReport;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\MetadataService\Statement\StatusReport;
use Webauthn\MetadataService\Utils;
use function array_key_exists;
use function count;
use function is_array;
use function is_string;

/**
 * @final
 */
class MetadataBLOBPayloadEntry implements JsonSerializable
{
    /**
     * @var string[]
     */
    public array $attestationCertificateKeyIdentifiers = [];

    /**
     * @var BiometricStatusReport[]
     */
    public array $biometricStatusReports = [];

    /**
     * @var StatusReport[]
     */
    public array $statusReports = [];

    /**
     * @param string[] $attestationCertificateKeyIdentifiers
     */
    public function __construct(
        public readonly ?string $aaid,
        public readonly ?string $aaguid,
        array $attestationCertificateKeyIdentifiers,
        public readonly ?MetadataStatement $metadataStatement,
        public readonly string $timeOfLastStatusChange,
        public readonly ?string $rogueListURL,
        public readonly ?string $rogueListHash
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
        $this->attestationCertificateKeyIdentifiers = $attestationCertificateKeyIdentifiers;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    /**
     * @return string[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getMetadataStatement(): ?MetadataStatement
    {
        return $this->metadataStatement;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addBiometricStatusReports(BiometricStatusReport ...$biometricStatusReports): self
    {
        foreach ($biometricStatusReports as $biometricStatusReport) {
            $this->biometricStatusReports[] = $biometricStatusReport;
        }

        return $this;
    }

    /**
     * @return BiometricStatusReport[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getBiometricStatusReports(): array
    {
        return $this->biometricStatusReports;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addStatusReports(StatusReport ...$statusReports): self
    {
        foreach ($statusReports as $statusReport) {
            $this->statusReports[] = $statusReport;
        }

        return $this;
    }

    /**
     * @return StatusReport[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getStatusReports(): array
    {
        return $this->statusReports;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getTimeOfLastStatusChange(): string
    {
        return $this->timeOfLastStatusChange;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRogueListURL(): string|null
    {
        return $this->rogueListURL;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRogueListHash(): string|null
    {
        return $this->rogueListHash;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        array_key_exists('timeOfLastStatusChange', $data) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "timeOfLastStatusChange" is missing'
        );
        array_key_exists('statusReports', $data) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "statusReports" is missing'
        );
        is_array($data['statusReports']) || throw MetadataStatementLoadingException::create(
            'Invalid data. The parameter "statusReports" shall be an array of StatusReport objects'
        );
        $object = new self(
            $data['aaid'] ?? null,
            $data['aaguid'] ?? null,
            $data['attestationCertificateKeyIdentifiers'] ?? [],
            isset($data['metadataStatement']) ? MetadataStatement::createFromArray($data['metadataStatement']) : null,
            $data['timeOfLastStatusChange'],
            $data['rogueListURL'] ?? null,
            $data['rogueListHash'] ?? null
        );
        foreach ($data['statusReports'] as $statusReport) {
            $object->statusReports[] = StatusReport::createFromArray($statusReport);
        }
        if (array_key_exists('biometricStatusReport', $data)) {
            foreach ($data['biometricStatusReport'] as $biometricStatusReport) {
                $object->biometricStatusReports[] = BiometricStatusReport::createFromArray($biometricStatusReport);
            }
        }

        return $object;
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
            'statusReports' => array_map(
                static fn (StatusReport $object): array => $object->jsonSerialize(),
                $this->statusReports
            ),
            'timeOfLastStatusChange' => $this->timeOfLastStatusChange,
            'rogueListURL' => $this->rogueListURL,
            'rogueListHash' => $this->rogueListHash,
        ];

        return Utils::filterNullValues($data);
    }
}
