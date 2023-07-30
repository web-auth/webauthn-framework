<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;
use function array_key_exists;

/**
 * @final
 */
class DisplayPNGCharacteristicsDescriptor implements JsonSerializable
{
    /**
     * @param RgbPaletteEntry[] $width
     */
    public function __construct(
        public readonly int $width,
        public readonly int $height,
        public readonly int $bitDepth,
        public readonly int $colorType,
        public readonly int $compression,
        public readonly int $filter,
        public readonly int $interlace,
        public array $plte,
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
    }

    /**
     * @param RgbPaletteEntry[] $plte
     */
    public static function create(
        int $width,
        int $height,
        int $bitDepth,
        int $colorType,
        int $compression,
        int $filter,
        int $interlace,
        array $plte
    ): self {
        return new self($width, $height, $bitDepth, $colorType, $compression, $filter, $interlace, $plte);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addPalettes(RgbPaletteEntry ...$rgbPaletteEntries): self
    {
        foreach ($rgbPaletteEntries as $rgbPaletteEntry) {
            $this->plte[] = $rgbPaletteEntry;
        }

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getWidth(): int
    {
        return $this->width;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getHeight(): int
    {
        return $this->height;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getBitDepth(): int
    {
        return $this->bitDepth;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getColorType(): int
    {
        return $this->colorType;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getCompression(): int
    {
        return $this->compression;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getFilter(): int
    {
        return $this->filter;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getInterlace(): int
    {
        return $this->interlace;
    }

    /**
     * @return RgbPaletteEntry[]
     * @deprecated since 4.7.0. Please use the property directly.
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
        return self::create(
            $data['width'],
            $data['height'],
            $data['bitDepth'],
            $data['colorType'],
            $data['compression'],
            $data['filter'],
            $data['interlace'],
            array_map(static fn (array $item) => RgbPaletteEntry::createFromArray($item), $data['plte'] ?? [])
        );
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
