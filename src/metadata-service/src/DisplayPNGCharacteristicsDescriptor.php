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

class DisplayPNGCharacteristicsDescriptor
{
    /**
     * @var int
     */
    private $width;

    /**
     * @var
     */
    private $height;

    /**
     * @var string
     */
    private $bitDepth;

    /**
     * @var string
     */
    private $colorType;

    /**
     * @var string
     */
    private $compression;

    /**
     * @var string
     */
    private $filter;

    /**
     * @var string
     */
    private $interlace;

    /**
     * @var rgbPaletteEntry[]
     */
    private $plte;


    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->id = $data['id'] ?? null;
        $object->tag = $data['tag'] ?? null;
        $object->data = $data['data'] ?? null;
        $object->fail_if_unknown = $data['fail_if_unknown'] ?? null;

        return $object;
    }
}
