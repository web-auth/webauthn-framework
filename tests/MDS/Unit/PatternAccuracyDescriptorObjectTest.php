<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Statement\PatternAccuracyDescriptor;

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
        static::assertSame($minComplexity, $object->getMinComplexity());
        static::assertSame($maxRetries, $object->getMaxRetries());
        static::assertSame($blockSlowdown, $object->getBlockSlowdown());
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public static function validObjectData(): iterable
    {
        yield [new PatternAccuracyDescriptor(10), 10, null, null, '{"minComplexity":10}'];
        yield [
            new PatternAccuracyDescriptor(10, 50, 15),
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

        new PatternAccuracyDescriptor($minComplexity, $maxRetries, $blockSlowdown);
    }

    public static function invalidObjectData(): iterable
    {
        yield [-1, null, null, 'Invalid data. The value of "minComplexity" must be a positive integer'];
        yield [11, -1, null, 'Invalid data. The value of "maxRetries" must be a positive integer'];
        yield [11, 1, -1, 'Invalid data. The value of "blockSlowdown" must be a positive integer'];
    }
}
