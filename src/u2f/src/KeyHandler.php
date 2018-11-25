<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace U2F;

use Base64Url\Base64Url;

class KeyHandler implements \JsonSerializable
{
    private $value;

    public function __construct(string $keyHandle)
    {
        $this->value = $keyHandle;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function jsonSerialize(): string
    {
        return Base64Url::encode($this->value);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
