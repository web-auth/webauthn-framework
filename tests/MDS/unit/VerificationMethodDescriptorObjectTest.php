<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Tests\Unit;

use const JSON_UNESCAPED_SLASHES;
use LogicException;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\BiometricAccuracyDescriptor;
use Webauthn\MetadataService\CodeAccuracyDescriptor;
use Webauthn\MetadataService\PatternAccuracyDescriptor;
use Webauthn\MetadataService\VerificationMethodDescriptor;

/**
 * @internal
 */
final class VerificationMethodDescriptorObjectTest extends TestCase
{
    /**
     * @test
     * @dataProvider validObjectData
     */
    public function validObject(VerificationMethodDescriptor $object, string $expectedJson): void
    {
        static::assertSame($expectedJson, json_encode($object, JSON_UNESCAPED_SLASHES));
    }

    public function validObjectData(): array
    {
        return [
            [
                new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT | VerificationMethodDescriptor::USER_VERIFY_PRESENCE,
                    null,
                    null,
                    null
                ),
                '{"userVerification":3}',
            ],
            [
                new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_ALL | VerificationMethodDescriptor::USER_VERIFY_EYEPRINT | VerificationMethodDescriptor::USER_VERIFY_HANDPRINT,
                    new CodeAccuracyDescriptor(35, 5),
                    new BiometricAccuracyDescriptor(0.12, null, null, null, null),
                    new PatternAccuracyDescriptor(50)
                ),
                '{"userVerification":1344,"caDesc":{"base":35,"minLength":5},"baDesc":{"FAR":0.12},"paDesc":{"minComplexity":50}}',
            ],
        ];
    }

    /**
     * @test
     * @dataProvider invalidObjectData
     */
    public function invalidObject(int $userVerification, string $expectedMessage): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($expectedMessage);

        new VerificationMethodDescriptor($userVerification, null, null, null);
    }

    public function invalidObjectData(): array
    {
        return [[-1, 'The parameter "userVerification" is invalid']];
    }
}
