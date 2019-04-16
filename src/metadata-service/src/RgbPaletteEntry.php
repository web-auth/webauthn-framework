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

class RgbPaletteEntry
{
    /**
     * @var float
     */
    private $r;

    /**
     * @var float
     */
    private $g;

    /**
     * @var float
     */
    private $b;

    public function getR(): float
    {
        return $this->r;
    }

    public function getG(): float
    {
        return $this->g;
    }

    public function getB(): float
    {
        return $this->b;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->r = $data['r'] ?? null;
        $object->g = $data['g'] ?? null;
        $object->b = $b['data'] ?? null;

        return $object;
    }
}
