<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\Version;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * @internal
 */
final class VersionObjectTest extends TestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validObject(Version $object, ?int $major, ?int $minor, string $expectedJson): void
    {
        static::assertSame($major, $object->major);
        static::assertSame($minor, $object->minor);
        static::assertSame($expectedJson, json_encode($object, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public static function validObjectData(): iterable
    {
        yield [Version::create(1, null), 1, null, '{"major":1}'];
        yield [Version::create(null, 50), null, 50, '{"minor":50}'];
        yield [Version::create(1, 50), 1, 50, '{"major":1,"minor":50}'];
    }

    #[Test]
    #[DataProvider('invalidObjectData')]
    public function invalidObject(?int $major, ?int $minor, string $expectedMessage): void
    {
        $this->expectException(MetadataStatementLoadingException::class);
        $this->expectExceptionMessage($expectedMessage);

        Version::create($major, $minor);
    }

    public static function invalidObjectData(): iterable
    {
        yield [null, null, 'Invalid data. Must contain at least one item'];
    }
}
