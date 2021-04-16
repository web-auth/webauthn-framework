<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use JetBrains\PhpStorm\Pure;
use JsonSerializable;

class BiometricStatusReport implements JsonSerializable
{
    private ?int $certLevel = null;

    private ?int $modality = null;

    private ?string $effectiveDate = null;

    private ?string $certificationDescriptor = null;

    private ?string $certificateNumber = null;

    private ?string $certificationPolicyVersion = null;

    private ?string $certificationRequirementsVersion = null;

    #[Pure]
    public function getCertLevel(): int
    {
        return $this->certLevel;
    }

    #[Pure]
    public function getModality(): int
    {
        return $this->modality;
    }

    #[Pure]
    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    #[Pure]
    public function getCertificationDescriptor(): ?string
    {
        return $this->certificationDescriptor;
    }

    #[Pure]
    public function getCertificateNumber(): ?string
    {
        return $this->certificateNumber;
    }

    #[Pure]
    public function getCertificationPolicyVersion(): ?string
    {
        return $this->certificationPolicyVersion;
    }

    #[Pure]
    public function getCertificationRequirementsVersion(): ?string
    {
        return $this->certificationRequirementsVersion;
    }

    #[Pure]
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

    #[Pure]
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

        return array_filter($data, static function ($var): bool {return null !== $var; });
    }
}
