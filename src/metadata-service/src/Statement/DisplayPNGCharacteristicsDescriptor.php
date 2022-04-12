<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use JsonSerializable;
use Webauthn\MetadataService\Utils;

class DisplayPNGCharacteristicsDescriptor implements JsonSerializable
{
    private readonly int $width;

    private readonly int $height;

    private readonly int $bitDepth;

    private readonly int $colorType;

    private readonly int $compression;

    private readonly int $filter;

    private readonly int $interlace;

    /**
     * @var RgbPaletteEntry[]
     */
    private array $plte = [];

    public function __construct(
        int $width,
        int $height,
        int $bitDepth,
        int $colorType,
        int $compression,
        int $filter,
        int $interlace
    ) {
        Assertion::greaterOrEqualThan($width, 0, 'Invalid width');
        Assertion::greaterOrEqualThan($height, 0, 'Invalid height');
        Assertion::range($bitDepth, 0, 254, 'Invalid bit depth');
        Assertion::range($colorType, 0, 254, 'Invalid color type');
        Assertion::range($compression, 0, 254, 'Invalid compression');
        Assertion::range($filter, 0, 254, 'Invalid filter');
        Assertion::range($interlace, 0, 254, 'Invalid interlace');

        $this->width = $width;
        $this->height = $height;
        $this->bitDepth = $bitDepth;
        $this->colorType = $colorType;
        $this->compression = $compression;
        $this->filter = $filter;
        $this->interlace = $interlace;
    }

    public function addPalettes(RgbPaletteEntry ...$rgbPaletteEntries): self
    {
        foreach ($rgbPaletteEntries as $rgbPaletteEntry) {
            $this->plte[] = $rgbPaletteEntry;
        }

        return $this;
    }

    public function getWidth(): int
    {
        return $this->width;
    }

    public function getHeight(): int
    {
        return $this->height;
    }

    public function getBitDepth(): int
    {
        return $this->bitDepth;
    }

    public function getColorType(): int
    {
        return $this->colorType;
    }

    public function getCompression(): int
    {
        return $this->compression;
    }

    public function getFilter(): int
    {
        return $this->filter;
    }

    public function getInterlace(): int
    {
        return $this->interlace;
    }

    /**
     * @return RgbPaletteEntry[]
     */
    public function getPaletteEntries(): array
    {
        return $this->plte;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        foreach ([
            'width',
            'compression',
            'height',
            'bitDepth',
            'colorType',
            'compression',
            'filter',
            'interlace',
        ] as $key) {
            Assertion::keyExists($data, $key, sprintf('Invalid data. The key "%s" is missing', $key));
        }
        $object = new self(
            $data['width'],
            $data['height'],
            $data['bitDepth'],
            $data['colorType'],
            $data['compression'],
            $data['filter'],
            $data['interlace']
        );
        if (isset($data['plte'])) {
            $plte = $data['plte'];
            Assertion::isArray($plte, 'Invalid "plte" parameter');
            foreach ($plte as $item) {
                $object->addPalettes(RgbPaletteEntry::createFromArray($item));
            }
        }

        return $object;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $data = [
            'width' => $this->width,
            'height' => $this->height,
            'bitDepth' => $this->bitDepth,
            'colorType' => $this->colorType,
            'compression' => $this->compression,
            'filter' => $this->filter,
            'interlace' => $this->interlace,
            'plte' => $this->plte,
        ];

        return Utils::filterNullValues($data);
    }
}
