<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Statement\BiometricAccuracyDescriptor;
use Webauthn\MetadataService\Statement\CodeAccuracyDescriptor;
use Webauthn\MetadataService\Statement\PatternAccuracyDescriptor;
use Webauthn\MetadataService\Statement\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Statement\VerificationMethodDescriptor;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * @internal
 */
final class VerificationMethodANDCombinationsObjectTest extends TestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validObject(VerificationMethodANDCombinations $object, string $expectedJson): void
    {
        static::assertSame($expectedJson, json_encode($object, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    public static function validObjectData(): iterable
    {
        yield [
            VerificationMethodANDCombinations::create([
                VerificationMethodDescriptor::create(
                    VerificationMethodDescriptor::USER_VERIFY_PATTERN_EXTERNAL,
                    CodeAccuracyDescriptor::create(35, 5),
                    BiometricAccuracyDescriptor::create(0.12, null, null, null, null),
                    PatternAccuracyDescriptor::create(50)
                ),
                VerificationMethodDescriptor::create(VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL),
            ]),
            '[{"userVerificationMethod":"pattern_external","caDesc":{"base":35,"minLength":5},"baDesc":{"selfAttestedFRR":0.12},"paDesc":{"minComplexity":50}},{"userVerificationMethod":"fingerprint_internal"}]',
        ];
    }
}
