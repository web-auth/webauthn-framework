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
interface DisplayPNGCharacteristicsDescriptorInterface extends JsonSerializable
{
    public function getWidth(): int;

    public function getHeight(): int;

    public function getBitDepth(): int;

    public function getColorType(): int;

    public function getCompression(): int;

    public function getFilter(): int;

    public function getInterlace(): int;

    /**
     * @return RgbPaletteEntryInterface[]
     */
    public function getPlte(): array;

    public function jsonSerialize(): array;
}
