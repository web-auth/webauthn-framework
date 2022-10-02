<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use function is_array;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
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
        $width >= 0 || throw MetadataStatementLoadingException::create('Invalid width');
        $height >= 0 || throw MetadataStatementLoadingException::create('Invalid height');
        ($bitDepth >= 0 && $bitDepth <= 254) || throw MetadataStatementLoadingException::create('Invalid bit depth');
        ($colorType >= 0 && $colorType <= 254) || throw MetadataStatementLoadingException::create(
            'Invalid color type'
        );
        ($compression >= 0 && $compression <= 254) || throw MetadataStatementLoadingException::create(
            'Invalid compression'
        );
        ($filter >= 0 && $filter <= 254) || throw MetadataStatementLoadingException::create('Invalid filter');
        ($interlace >= 0 && $interlace <= 254) || throw MetadataStatementLoadingException::create(
            'Invalid interlace'
        );

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
            array_key_exists($key, $data) || throw MetadataStatementLoadingException::create(sprintf(
                'Invalid data. The key "%s" is missing',
                $key
            ));
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
            is_array($plte) || throw MetadataStatementLoadingException::create('Invalid "plte" parameter');
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
