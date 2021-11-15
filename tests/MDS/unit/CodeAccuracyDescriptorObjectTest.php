<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Tests\Unit;

use const JSON_UNESCAPED_SLASHES;
use LogicException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\CodeAccuracyDescriptor;

/**
 * @internal
 */
final class CodeAccuracyDescriptorObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(
        CodeAccuracyDescriptor $object,
        int $base,
        int $minLength,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedJson
    ): void {
        static::assertSame($base, $object->getBase());
        static::assertSame($minLength, $object->getMinLength());
        static::assertSame($maxRetries, $object->getMaxRetries());
        static::assertSame($blockSlowdown, $object->getBlockSlowdown());
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public function validObjectData(): array
    {
        return [
            [new CodeAccuracyDescriptor(10, 4), 10, 4, null, null, '{"base":10,"minLength":4}'],
            [
                new CodeAccuracyDescriptor(10, 4, 50, 15),
                10,
                4,
                50,
                15,
                '{"base":10,"minLength":4,"maxRetries":50,"blockSlowdown":15}',
            ],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(
        int $base,
        int $minLength,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedMessage
    ): void {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new CodeAccuracyDescriptor($base, $minLength, $maxRetries, $blockSlowdown);
    }

    public function invalidObjectData(): array
    {
        return [
            [-1, -1, null, null, 'Invalid data. The value of "base" must be a positive integer'],
            [11, -1, -1, null, 'Invalid data. The value of "minLength" must be a positive integer'],
            [11, 1, -1, -1, 'Invalid data. The value of "maxRetries" must be a positive integer'],
            [11, 1, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'],
        ];
    }
}
