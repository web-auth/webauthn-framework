<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\MetadataService\Statement\BiometricAccuracyDescriptor;
use Webauthn\MetadataService\Statement\CodeAccuracyDescriptor;
use Webauthn\MetadataService\Statement\PatternAccuracyDescriptor;
use Webauthn\MetadataService\Statement\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Statement\VerificationMethodDescriptor;

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
            (new VerificationMethodANDCombinations())
                ->addVerificationMethodDescriptor(new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_PATTERN_EXTERNAL,
                    new CodeAccuracyDescriptor(35, 5),
                    new BiometricAccuracyDescriptor(0.12, null, null, null, null),
                    new PatternAccuracyDescriptor(50)
                ))
                ->addVerificationMethodDescriptor(new VerificationMethodDescriptor(
                    VerificationMethodDescriptor::USER_VERIFY_FINGERPRINT_INTERNAL
                )),
            '[{"userVerificationMethod":"pattern_external","caDesc":{"base":35,"minLength":5},"baDesc":{"selfAttestedFRR":0.12},"paDesc":{"minComplexity":50}},{"userVerificationMethod":"fingerprint_internal"}]',
        ];
    }
}
