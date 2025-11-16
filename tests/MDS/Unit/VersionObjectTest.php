<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\Version;

/**
 * @internal
 */
final class VersionObjectTest extends MdsTestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validVersionSerializesCorrectly(
        Version $object,
        ?int $major,
        ?int $minor,
        string $expectedJson
    ): void {
        // Given
        // Object provided by data provider

        // When
        $serialized = $this->getSerializer()
            ->serialize($object, JsonEncoder::FORMAT, [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame($major, $object->major);
        static::assertSame($minor, $object->minor);
        static::assertSame($expectedJson, $serialized);
    }

    public static function validObjectData(): iterable
    {
        yield [Version::create(1, null), 1, null, '{"major":1}'];
        yield [Version::create(null, 50), null, 50, '{"minor":50}'];
        yield [Version::create(1, 50), 1, 50, '{"major":1,"minor":50}'];
    }

    #[Test]
    #[DataProvider('invalidObjectData')]
    public function creatingVersionWithInvalidValuesThrowsException(
        ?int $major,
        ?int $minor,
        string $expectedMessage
    ): void {
        // Then
        $this->expectException(MetadataStatementLoadingException::class);
        $this->expectExceptionMessage($expectedMessage);

        // Given
        // Parameters provided by data provider

        // When
        Version::create($major, $minor);
    }

    public static function invalidObjectData(): iterable
    {
        yield [null, null, 'Invalid data. Must contain at least one item'];
    }
}
