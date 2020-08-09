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

interface EcdaaTrustAnchorInterface extends JsonSerializable
{
    public function getX(): string;

    public function getY(): string;

    public function getC(): string;

    public function getSx(): string;

    public function getSy(): string;

    public function getG1Curve(): string;

    public function jsonSerialize(): array;
}
