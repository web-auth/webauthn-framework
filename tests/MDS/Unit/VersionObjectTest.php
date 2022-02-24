<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use const JSON_UNESCAPED_SLASHES;
use LogicException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Version;

/**
 * @internal
 */
final class VersionObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(Version $object, ?int $major, ?int $minor, string $expectedJson): void
    {
        static::assertSame($major, $object->getMajor());
        static::assertSame($minor, $object->getMinor());
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public function validObjectData(): array
    {
        return [
            [new Version(1, null), 1, null, '{"major":1}'],
            [new Version(null, 50), null, 50, '{"minor":50}'],
            [new Version(1, 50), 1, 50, '{"major":1,"minor":50}'],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(?int $major, ?int $minor, string $expectedMessage): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new Version($major, $minor);
    }

    public function invalidObjectData(): array
    {
        return [[null, null, 'Invalid data. Must contain at least one item']];
    }
}
