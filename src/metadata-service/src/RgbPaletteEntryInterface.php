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
interface RgbPaletteEntryInterface extends JsonSerializable
{
    public function getR(): int;

    public function getG(): int;

    public function getB(): int;

    public function jsonSerialize(): array;
}
