<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

/**
 */
class BiometricStatusReport implements \JsonSerializable
{
    /**
     * @var int
     */
    private $certLevel;

    /**
     * @var int
     */
    private $modality;

    /**
     * @var string|null
     */
    private $effectiveDate;

    /**
     * @var string|null
     */
    private $certificationDescriptor;

    /**
     * @var string|null
     */
    private $certificateNumber;

    /**
     * @var string|null
     */
    private $certificationPolicyVersion;

    /**
     * @var string|null
     */
    private $certificationRequirementsVersion;

    public function getCertLevel(): int
    {
        return $this->certLevel;
    }

    public function setCertLevel(int $certLevel): void
    {
        $this->certLevel = $certLevel;
    }

    public function getModality(): int
    {
        return $this->modality;
    }

    public function setModality(int $modality): void
    {
        $this->modality = $modality;
    }

    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    public function setEffectiveDate(?string $effectiveDate): void
    {
        $this->effectiveDate = $effectiveDate;
    }

    public function getCertificationDescriptor(): ?string
    {
        return $this->certificationDescriptor;
    }

    public function setCertificationDescriptor(?string $certificationDescriptor): void
    {
        $this->certificationDescriptor = $certificationDescriptor;
    }

    public function getCertificateNumber(): ?string
    {
        return $this->certificateNumber;
    }

    public function setCertificateNumber(?string $certificateNumber): void
    {
        $this->certificateNumber = $certificateNumber;
    }

    public function getCertificationPolicyVersion(): ?string
    {
        return $this->certificationPolicyVersion;
    }

    public function setCertificationPolicyVersion(?string $certificationPolicyVersion): void
    {
        $this->certificationPolicyVersion = $certificationPolicyVersion;
    }

    public function getCertificationRequirementsVersion(): ?string
    {
        return $this->certificationRequirementsVersion;
    }

    public function setCertificationRequirementsVersion(?string $certificationRequirementsVersion): void
    {
        $this->certificationRequirementsVersion = $certificationRequirementsVersion;
    }

    public function jsonSerialize(): array
    {
        return [
        ];
    }
}
