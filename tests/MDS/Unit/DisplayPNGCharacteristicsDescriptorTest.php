<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Statement\DisplayPNGCharacteristicsDescriptor;

/**
 * @internal
 */
final class DisplayPNGCharacteristicsDescriptorTest extends TestCase
{
    /**
     * @test
     * @dataProvider getInvalidValues
     */
    public function validObject(
        int $width,
        int $height,
        int $bitDepth,
        int $colorType,
        int $compression,
        int $filter,
        int $interlace,
        string $message
    ): void {
        //Then
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage($message);

        //When
        DisplayPNGCharacteristicsDescriptor::createFromArray([
            'width' => $width,
            'height' => $height,
            'bitDepth' => $bitDepth,
            'colorType' => $colorType,
            'compression' => $compression,
            'filter' => $filter,
            'interlace' => $interlace,
        ]);
    }

    /**
     * @return array<int|string>[]
     */
    public function getInvalidValues(): iterable
    {
        yield [-1, 0, 0, 0, 0, 0, 0, 'Invalid width'];
        yield [0, -1, 0, 0, 0, 0, 0, 'Invalid height'];
        yield [0, 0, -1, 0, 0, 0, 0, 'Invalid bit depth'];
        yield [0, 0, 255, 0, 0, 0, 0, 'Invalid bit depth'];
        yield [0, 0, 0, -1, 0, 0, 0, 'Invalid color type'];
        yield [0, 0, 0, 255, 0, 0, 0, 'Invalid color type'];
        yield [0, 0, 0, 0, -1, 0, 0, 'Invalid compression'];
        yield [0, 0, 0, 0, 255, 0, 0, 'Invalid compression'];
        yield [0, 0, 0, 0, 0, -1, 0, 'Invalid filter'];
        yield [0, 0, 0, 0, 0, 255, 0, 'Invalid filter'];
        yield [0, 0, 0, 0, 0, 0, -1, 'Invalid interlace'];
        yield [0, 0, 0, 0, 0, 0, 255, 'Invalid interlace'];
    }
}
