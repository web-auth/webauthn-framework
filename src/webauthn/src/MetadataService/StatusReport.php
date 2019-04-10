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
class StatusReport implements \JsonSerializable
{
    /**
     * @var string
     *
     * @see AuthenticatorStatus
     */
    private $status;

    /**
     * @var string|null
     */
    private $effectiveDate;

    /**
     * @var string|null
     */
    private $certificate;

    /**
     * @var string|null
     */
    private $url;

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

    public function getStatus(): string
    {
        return $this->status;
    }

    public function setStatus(string $status): void
    {
        $this->status = $status;
    }

    public function getEffectiveDate(): ?string
    {
        return $this->effectiveDate;
    }

    public function setEffectiveDate(?string $effectiveDate): void
    {
        $this->effectiveDate = $effectiveDate;
    }

    public function getCertificate(): ?string
    {
        return $this->certificate;
    }

    public function setCertificate(?string $certificate): void
    {
        $this->certificate = $certificate;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): void
    {
        $this->url = $url;
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
            'status' => $this->status,
            'effectiveDate' => $this->effectiveDate,
            'certificate' => $this->certificate,
            'url' => $this->url,
            'certificationDescriptor' => $this->certificationDescriptor,
            'certificateNumber' => $this->certificateNumber,
            'certificationPolicyVersion' => $this->certificationPolicyVersion,
        ];
    }
}
