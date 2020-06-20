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
use Webauthn\MetadataService\CodeAccuracyDescriptor;
use Webauthn\MetadataService\PatternAccuracyDescriptor;
use Webauthn\MetadataService\VerificationMethodANDCombinations;
use Webauthn\MetadataService\VerificationMethodDescriptor;

/**
 * @group unit
 * @group Fido2
 *
 * @internal
 */
class VerificationMethodANDCombinationsObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(VerificationMethodANDCombinations $object, string $expectedJson): void
    {
        static::assertEquals($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));

        $loaded = VerificationMethodANDCombinations::createFromArray(json_decode($expectedJson, true));
        static::assertEquals($object, $loaded);
    }

    public function validObjectData(): array
    {
        return [
            [
                (new VerificationMethodANDCombinations())
                    ->addVerificationMethodDescriptor(new VerificationMethodDescriptor(
                        VerificationMethodDescriptor::USER_VERIFY_ALL | VerificationMethodDescriptor::USER_VERIFY_EYEPRINT | VerificationMethodDescriptor::USER_VERIFY_HANDPRINT,
                        new CodeAccuracyDescriptor(35, 5),
                        new BiometricAccuracyDescriptor(0.12, null, null, null, null),
                        new PatternAccuracyDescriptor(50)
                    ))
                    ->addVerificationMethodDescriptor(new VerificationMethodDescriptor(
                        VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT | VerificationMethodDescriptor::USER_VERIFY_PRESENCE
                    )),
                '[{"userVerification":1344,"caDesc":{"base":35,"minLength":5},"baDesc":{"FAR":0.12},"paDesc":{"minComplexity":50}},{"userVerification":3}]',
            ],
        ];
    }
}
