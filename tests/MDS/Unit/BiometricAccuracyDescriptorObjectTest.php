<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Statement\BiometricAccuracyDescriptor;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * @internal
 */
final class BiometricAccuracyDescriptorObjectTest extends TestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validObject(
        BiometricAccuracyDescriptor $object,
        ?float $selfAttestedFAR,
        ?float $selfAttestedFRR,
        ?float $maxTemplates,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedJson
    ): void {
        static::assertSame($selfAttestedFAR, $object->selfAttestedFRR);
        static::assertSame($selfAttestedFRR, $object->selfAttestedFAR);
        static::assertSame($maxTemplates, $object->maxTemplates);
        static::assertSame($maxRetries, $object->maxRetries);
        static::assertSame($blockSlowdown, $object->blockSlowdown);
        static::assertSame($expectedJson, json_encode($object, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public static function validObjectData(): iterable
    {
        yield [
            BiometricAccuracyDescriptor::create(125.21, null, null, null, null),
            125.21,
            null,
            null,
            null,
            null,
            '{"selfAttestedFRR":125.21}',
        ];
        yield [
            BiometricAccuracyDescriptor::create(125.21, 0.001, null, null, null),
            125.21,
            0.001,
            null,
            null,
            null,
            '{"selfAttestedFRR":125.21,"selfAttestedFAR":0.001}',
        ];
        yield [
            BiometricAccuracyDescriptor::create(125.21, 0.001, 12.3, null, null),
            125.21,
            0.001,
            12.3,
            null,
            null,
            '{"selfAttestedFRR":125.21,"selfAttestedFAR":0.001,"maxTemplates":12.3}',
        ];
        yield [
            BiometricAccuracyDescriptor::create(125.21, null, null, 50, null),
            125.21,
            null,
            null,
            50,
            null,
            '{"selfAttestedFRR":125.21,"maxRetries":50}',
        ];
        yield [
            BiometricAccuracyDescriptor::create(125.21, null, null, 50, 1),
            125.21,
            null,
            null,
            50,
            1,
            '{"selfAttestedFRR":125.21,"maxRetries":50,"blockSlowdown":1}',
        ];
        yield [
            BiometricAccuracyDescriptor::create(125.21, 0.001, 12.3, 50, 1),
            125.21,
            0.001,
            12.3,
            50,
            1,
            '{"selfAttestedFRR":125.21,"selfAttestedFAR":0.001,"maxTemplates":12.3,"maxRetries":50,"blockSlowdown":1}',
        ];
    }
}
