<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\BiometricAccuracyDescriptor;

/**
 * @internal
 */
final class BiometricAccuracyDescriptorObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(
        BiometricAccuracyDescriptor $object,
        ?float $FAR,
        ?float $FRR,
        ?float $EER,
        ?float $FAAR,
        ?int $maxReferenceDataSets,
        ?int $maxRetries,
        ?int $blockSlowdown,
        string $expectedJson
    ): void {
        static::assertSame($FAR, $object->getFAR());
        static::assertSame($FRR, $object->getFRR());
        static::assertSame($EER, $object->getEER());
        static::assertSame($FAAR, $object->getFAAR());
        static::assertSame($maxReferenceDataSets, $object->getMaxReferenceDataSets());
        static::assertSame($maxRetries, $object->getMaxRetries());
        static::assertSame($blockSlowdown, $object->getBlockSlowdown());
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public function validObjectData(): array
    {
        return [
            [
                new BiometricAccuracyDescriptor(125.21, null, null, null, null),
                125.21,
                null,
                null,
                null,
                null,
                null,
                null,
                '{"FAR":125.21}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, 0.001, null, null, null),
                125.21,
                0.001,
                null,
                null,
                null,
                null,
                null,
                '{"FAR":125.21,"FRR":0.001}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, 0.001, 12.3, null, null),
                125.21,
                0.001,
                12.3,
                null,
                null,
                null,
                null,
                '{"FAR":125.21,"FRR":0.001,"EER":12.3}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, null, null, 25.6, null),
                125.21,
                null,
                null,
                25.6,
                null,
                null,
                null,
                '{"FAR":125.21,"FAAR":25.6}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, null, null, 25.6, 15),
                125.21,
                null,
                null,
                25.6,
                15,
                null,
                null,
                '{"FAR":125.21,"FAAR":25.6,"maxReferenceDataSets":15}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, null, null, 25.6, 15, 50, 1),
                125.21,
                null,
                null,
                25.6,
                15,
                50,
                1,
                '{"FAR":125.21,"FAAR":25.6,"maxReferenceDataSets":15,"maxRetries":50,"blockSlowdown":1}',
            ],
            [
                new BiometricAccuracyDescriptor(125.21, 0.001, 12.3, 25.6, 15, 50, 1),
                125.21,
                0.001,
                12.3,
                25.6,
                15,
                50,
                1,
                '{"FAR":125.21,"FRR":0.001,"EER":12.3,"FAAR":25.6,"maxReferenceDataSets":15,"maxRetries":50,"blockSlowdown":1}',
            ],
        ];
    }
}
