<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
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
        static::assertSame($expectedJson, json_encode($object, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public function validObjectData(): array
    {
        return [
            [
                new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL,
                    null,
                    null,
                    null
                ),
                '{"userVerificationMethod":"fingerprint_internal"}',
            ],
            [
                new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_PATTERN_EXTERNAL,
                    new CodeAccuracyDescriptor(35, 5),
                    new BiometricAccuracyDescriptor(0.12, null, null, null, null),
                    new PatternAccuracyDescriptor(50)
                ),
                '{"userVerificationMethod":"pattern_external","caDesc":{"base":35,"minLength":5},"baDesc":{"FAR":0.12},"paDesc":{"minComplexity":50}}',
            ],
        ];
    }
}
