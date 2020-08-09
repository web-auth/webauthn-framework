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

interface MetadataTOCPayloadEntryInterface extends JsonSerializable
{
    public function getAaid(): ?string;

    public function getAaguid(): ?string;

    public function getAttestationCertificateKeyIdentifiers(): array;

    public function getHash(): ?string;

    public function getUrl(): ?string;

    /**
     * @return StatusReportInterface[]
     */
    public function getStatusReports(): array;

    public function getTimeOfLastStatusChange(): string;

    public function getRogueListURL(): string;

    public function getRogueListHash(): string;

    public function jsonSerialize(): array;
}
