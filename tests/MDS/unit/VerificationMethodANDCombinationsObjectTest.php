<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Tests\Unit;

use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\BiometricAccuracyDescriptor;
use Webauthn\MetadataService\CodeAccuracyDescriptor;
use Webauthn\MetadataService\PatternAccuracyDescriptor;
use Webauthn\MetadataService\VerificationMethodANDCombinations;
use Webauthn\MetadataService\VerificationMethodDescriptor;

/**
 * @internal
 */
final class VerificationMethodANDCombinationsObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(VerificationMethodANDCombinations $object, string $expectedJson): void
    {
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
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
