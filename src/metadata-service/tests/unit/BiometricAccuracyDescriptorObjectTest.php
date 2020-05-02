<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\BiometricAccuracyDescriptor;

/**
 * @group unit
 * @group Fido2
 */
class BiometricAccuracyDescriptorObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(BiometricAccuracyDescriptor $object, ?float $FAR, ?float $FRR, ?float $EER, ?float $FAAR, ?int $maxReferenceDataSets, ?int $maxRetries, ?int $blockSlowdown, string $expectedJson): void
    {
        static::assertEquals($FAR, $object->getFAR());
        static::assertEquals($FRR, $object->getFRR());
        static::assertEquals($EER, $object->getEER());
        static::assertEquals($FAAR, $object->getFAAR());
        static::assertEquals($maxReferenceDataSets, $object->getMaxReferenceDataSets());
        static::assertEquals($maxRetries, $object->getMaxRetries());
        static::assertEquals($blockSlowdown, $object->getBlockSlowdown());
        static::assertEquals($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));

        $loaded = BiometricAccuracyDescriptor::createFromArray(json_decode($expectedJson, true));
        static::assertEquals($object, $loaded);
    }

    public function validObjectData(): array
    {
        return [
            [new BiometricAccuracyDescriptor(125.21, null, null, null, null), 125.21, null, null, null, null, null, null, '{"FAR":125.21}'],
            [new BiometricAccuracyDescriptor(125.21, 0.001, null, null, null), 125.21, 0.001, null, null, null, null, null, '{"FAR":125.21,"FRR":0.001}'],
            [new BiometricAccuracyDescriptor(125.21, 0.001, 12.3, null, null), 125.21, 0.001, 12.3, null, null, null, null, '{"FAR":125.21,"FRR":0.001,"EER":12.3}'],
            [new BiometricAccuracyDescriptor(125.21, null, null, 25.6, null), 125.21, null, null, 25.6, null, null, null, '{"FAR":125.21,"FAAR":25.6}'],
            [new BiometricAccuracyDescriptor(125.21, null, null, 25.6, 15), 125.21, null, null, 25.6, 15, null, null, '{"FAR":125.21,"FAAR":25.6,"maxReferenceDataSets":15}'],
            [new BiometricAccuracyDescriptor(125.21, null, null, 25.6, 15, 50, 1), 125.21, null, null, 25.6, 15, 50, 1, '{"FAR":125.21,"FAAR":25.6,"maxReferenceDataSets":15,"maxRetries":50,"blockSlowdown":1}'],
            [new BiometricAccuracyDescriptor(125.21, 0.001, 12.3, 25.6, 15, 50, 1), 125.21, 0.001, 12.3, 25.6, 15, 50, 1, '{"FAR":125.21,"FRR":0.001,"EER":12.3,"FAAR":25.6,"maxReferenceDataSets":15,"maxRetries":50,"blockSlowdown":1}'],
        ];
    }
}
