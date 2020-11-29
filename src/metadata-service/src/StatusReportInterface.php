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

use JsonSerializable;

/**
 * @internal
 */
interface StatusReportInterface extends JsonSerializable
{
    public function isCompromised(): bool;

    public function getStatus(): string;

    public function getEffectiveDate(): ?string;

    public function getCertificate(): ?string;

    public function getUrl(): ?string;

    public function getCertificationDescriptor(): ?string;

    public function getCertificateNumber(): ?string;

    public function getCertificationPolicyVersion(): ?string;

    public function getCertificationRequirementsVersion(): ?string;

    public function jsonSerialize(): array;
}
