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

use Assert\Assertion;

class DisplayPNGCharacteristicsDescriptor
{
    /**
     * @var float
     */
    private $width;

    /**
     * @var float
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
     * @var RgbPaletteEntry[]
     */
    private $plte = [];

    public function getWidth(): float
    {
        return $this->width;
    }

    public function getHeight(): float
    {
        return $this->height;
    }

    public function getBitDepth(): string
    {
        return $this->bitDepth;
    }

    public function getColorType(): string
    {
        return $this->colorType;
    }

    public function getCompression(): string
    {
        return $this->compression;
    }

    public function getFilter(): string
    {
        return $this->filter;
    }

    public function getInterlace(): string
    {
        return $this->interlace;
    }

    /**
     * @return RgbPaletteEntry[]
     */
    public function getPlte(): array
    {
        return $this->plte;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->width = $data['width'] ?? null;
        $object->compression = $data['compression'] ?? null;
        $object->height = $data['height'] ?? null;
        $object->bitDepth = $data['bitDepth'] ?? null;
        $object->colorType = $data['colorType'] ?? null;
        $object->compression = $data['compression'] ?? null;
        $object->filter = $data['filter'] ?? null;
        $object->interlace = $data['interlace'] ?? null;
        if (isset($data['plte'])) {
            $plte = $data['plte'];
            Assertion::isArray($plte, 'Invalid "plte" parameter');
            foreach ($plte as $item) {
                $object->plte[] = RgbPaletteEntry::createFromArray($item);
            }
        }

        return $object;
    }
}
