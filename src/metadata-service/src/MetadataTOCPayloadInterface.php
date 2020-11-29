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
interface MetadataTOCPayloadInterface extends JsonSerializable
{
    public function getLegalHeader(): ?string;

    public function getNo(): int;

    public function getNextUpdate(): string;

    /**
     * @return MetadataTOCPayloadEntryInterface[]
     */
    public function getEntries(): array;

    public function jsonSerialize(): array;
}
