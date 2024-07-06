<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\DisplayPNGCharacteristicsDescriptor;

/**
 * @internal
 */
final class DisplayPNGCharacteristicsDescriptorTest extends MdsTestCase
{
    #[Test]
    #[DataProvider('getInvalidValues')]
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
        static::expectException(MetadataStatementLoadingException::class);
        static::expectExceptionMessage($message);

        //When
        DisplayPNGCharacteristicsDescriptor::create(
            width: $width,
            height: $height,
            bitDepth: $bitDepth,
            colorType: $colorType,
            compression: $compression,
            filter: $filter,
            interlace: $interlace,
        );
    }

    /**
     * @return array<int|string>[]
     */
    public static function getInvalidValues(): iterable
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
