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
class MetadataTOCPayloadEntry implements \JsonSerializable
{
    /**
     * @var string|null
     */
    private $aaid;

    /**
     * @var string|null
     */
    private $aaguid;

    /**
     * @var string[]
     */
    private $attestationCertificateKeyIdentifiers;

    /**
     * @var string|null
     */
    private $hash;

    /**
     * @var string|null
     */
    private $url;

    /**
     * @var BiometricStatusReport[]
     */
    private $biometricStatusReports;

    /**
     * @var string
     */
    private $statusReports;

    /**
     * @var string
     */
    private $timeOfLastStatusChange;

    /**
     * @var string
     */
    private $rogueListURL;

    /**
     * @var string
     */
    private $rogueListHash;

    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    public function setAaid(?string $aaid): void
    {
        $this->aaid = $aaid;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function setAaguid(?string $aaguid): void
    {
        $this->aaguid = $aaguid;
    }

    /**
     * @return string[]
     */
    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    public function setAttestationCertificateKeyIdentifiers(array $attestationCertificateKeyIdentifiers): void
    {
        $this->attestationCertificateKeyIdentifiers = $attestationCertificateKeyIdentifiers;
    }

    public function getHash(): ?string
    {
        return $this->hash;
    }

    public function setHash(?string $hash): void
    {
        $this->hash = $hash;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): void
    {
        $this->url = $url;
    }

    /**
     * @return BiometricStatusReport[]
     */
    public function getBiometricStatusReports(): array
    {
        return $this->biometricStatusReports;
    }

    public function addBiometricStatusReports(BiometricStatusReport $biometricStatusReport): void
    {
        $this->biometricStatusReports[] = $biometricStatusReport;
    }

    public function getStatusReports(): string
    {
        return $this->statusReports;
    }

    public function setStatusReports(string $statusReports): void
    {
        $this->statusReports = $statusReports;
    }

    public function getTimeOfLastStatusChange(): string
    {
        return $this->timeOfLastStatusChange;
    }

    public function setTimeOfLastStatusChange(string $timeOfLastStatusChange): void
    {
        $this->timeOfLastStatusChange = $timeOfLastStatusChange;
    }

    public function getRogueListURL(): string
    {
        return $this->rogueListURL;
    }

    public function setRogueListURL(string $rogueListURL): void
    {
        $this->rogueListURL = $rogueListURL;
    }

    public function getRogueListHash(): string
    {
        return $this->rogueListHash;
    }

    public function setRogueListHash(string $rogueListHash): void
    {
        $this->rogueListHash = $rogueListHash;
    }

    public function jsonSerialize(): array
    {
        return [
        ];
    }
}
