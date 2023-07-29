<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\PatternAccuracyDescriptor;
use const JSON_UNESCAPED_SLASHES;

/**
 * @internal
 */
final class PatternAccuracyDescriptorObjectTest extends TestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validObject(
        PatternAccuracyDescriptor $object,
        int $minComplexity,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedJson
    ): void {
        static::assertSame($minComplexity, $object->minComplexity);
        static::assertSame($maxRetries, $object->maxRetries);
        static::assertSame($blockSlowdown, $object->blockSlowdown);
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public static function validObjectData(): iterable
    {
        yield [PatternAccuracyDescriptor::create(10), 10, null, null, '{"minComplexity":10}'];
        yield [
            PatternAccuracyDescriptor::create(10, 50, 15),
            10,
            50,
            15,
            '{"minComplexity":10,"maxRetries":50,"blockSlowdown":15}',
        ];
    }

    #[Test]
    #[DataProvider('invalidObjectData')]
    public function invalidObject(
        int $minComplexity,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedMessage
    ): void {
        $this->expectException(MetadataStatementLoadingException::class);
        $this->expectExceptionMessage($expectedMessage);

        PatternAccuracyDescriptor::create($minComplexity, $maxRetries, $blockSlowdown);
    }

    public static function invalidObjectData(): iterable
    {
        yield [-1, null, null, 'Invalid data. The value of "minComplexity" must be a positive integer'];
        yield [11, -1, null, 'Invalid data. The value of "maxRetries" must be a positive integer'];
        yield [11, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'];
    }
}
