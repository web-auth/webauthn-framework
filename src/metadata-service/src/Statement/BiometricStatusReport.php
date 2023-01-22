<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

/**
 * @final
 */
class BiometricStatusReport implements JsonSerializable
{
    private ?int $certLevel = null;

    private ?int $modality = null;

    private ?string $effectiveDate = null;

    private ?string $certificationDescriptor = null;

    private ?string $certificateNumber = null;

    private ?string $certificationPolicyVersion = null;

    private ?string $certificationRequirementsVersion = null;

    public function getCertLevel(): int|null
    {
        return $this->certLevel;
    }

    public function getModality(): int|null
    {
        return $this->modality;
    }

    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    public function getCertificationDescriptor(): ?string
    {
        return $this->certificationDescriptor;
    }

    public function getCertificateNumber(): ?string
    {
        return $this->certificateNumber;
    }

    public function getCertificationPolicyVersion(): ?string
    {
        return $this->certificationPolicyVersion;
    }

    public function getCertificationRequirementsVersion(): ?string
    {
        return $this->certificationRequirementsVersion;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->certLevel = $data['certLevel'] ?? null;
        $object->modality = $data['modality'] ?? null;
        $object->effectiveDate = $data['effectiveDate'] ?? null;
        $object->certificationDescriptor = $data['certificationDescriptor'] ?? null;
        $object->certificateNumber = $data['certificateNumber'] ?? null;
        $object->certificationPolicyVersion = $data['certificationPolicyVersion'] ?? null;
        $object->certificationRequirementsVersion = $data['certificationRequirementsVersion'] ?? null;

        return $object;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'certLevel' => $this->certLevel,
            'modality' => $this->modality,
            'effectiveDate' => $this->effectiveDate,
            'certificationDescriptor' => $this->certificationDescriptor,
            'certificateNumber' => $this->certificateNumber,
            'certificationPolicyVersion' => $this->certificationPolicyVersion,
            'certificationRequirementsVersion' => $this->certificationRequirementsVersion,
        ];

        return array_filter($data, static fn ($var): bool => $var !== null);
    }
}
