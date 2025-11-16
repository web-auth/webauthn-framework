<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\CodeAccuracyDescriptor;

/**
 * @internal
 */
final class CodeAccuracyDescriptorObjectTest extends MdsTestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validCodeAccuracyDescriptorSerializesCorrectly(
        CodeAccuracyDescriptor $object,
        int $base,
        int $minLength,
        ?int $maxRetries,
        ?int $blockSlowdown,
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
        static::assertSame($base, $object->base);
        static::assertSame($minLength, $object->minLength);
        static::assertSame($maxRetries, $object->maxRetries);
        static::assertSame($blockSlowdown, $object->blockSlowdown);
        static::assertSame($expectedJson, $serialized);
    }

    public static function validObjectData(): iterable
    {
        yield [CodeAccuracyDescriptor::create(10, 4), 10, 4, null, null, '{"base":10,"minLength":4}'];
        yield [
            CodeAccuracyDescriptor::create(10, 4, 50, 15),
            10,
            4,
            50,
            15,
            '{"base":10,"minLength":4,"maxRetries":50,"blockSlowdown":15}',
        ];
    }

    #[Test]
    #[DataProvider('invalidObjectData')]
    public function creatingCodeAccuracyDescriptorWithInvalidValuesThrowsException(
        int $base,
        int $minLength,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedMessage
    ): void {
        // Then
        $this->expectException(MetadataStatementLoadingException::class);
        $this->expectExceptionMessage($expectedMessage);

        // Given
        // Parameters provided by data provider

        // When
        CodeAccuracyDescriptor::create($base, $minLength, $maxRetries, $blockSlowdown);
    }

    public static function invalidObjectData(): iterable
    {
        yield [-1, -1, null, null, 'Invalid data. The value of "base" must be a positive integer'];
        yield [11, -1, -1, null, 'Invalid data. The value of "minLength" must be a positive integer'];
        yield [11, 1, -1, -1, 'Invalid data. The value of "maxRetries" must be a positive integer'];
        yield [11, 1, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'];
    }
}
