<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\MetadataService\Statement\BiometricAccuracyDescriptor;
use Webauthn\MetadataService\Statement\CodeAccuracyDescriptor;
use Webauthn\MetadataService\Statement\PatternAccuracyDescriptor;
use Webauthn\MetadataService\Statement\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Statement\VerificationMethodDescriptor;

/**
 * @internal
 */
final class VerificationMethodANDCombinationsObjectTest extends MdsTestCase
{
    #[Test]
    #[DataProvider('validObjectData')]
    public function validObject(VerificationMethodANDCombinations $object, string $expectedJson): void
    {
        static::assertSame($expectedJson, $this->getSerializer()->serialize($object, JsonEncoder::FORMAT, [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
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
