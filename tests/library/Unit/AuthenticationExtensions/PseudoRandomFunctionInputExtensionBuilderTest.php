<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtension;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtensionBuilder;
use Webauthn\Exception\AuthenticationExtensionException;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PseudoRandomFunctionInputExtensionBuilderTest extends AbstractTestCase
{
    #[Test]
    public function builderProducesPrfExtensionNamedPrf(): void
    {
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs('salt-bytes')
            ->build();

        static::assertInstanceOf(PseudoRandomFunctionInputExtension::class, $extension);
        static::assertSame('prf', $extension->name);
    }

    #[Test]
    public function singleInputIsBase64UrlEncodedUnderEvalFirst(): void
    {
        $raw = "\x00\x01\x02\x03salty";
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs($raw)
            ->build();

        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded($raw),
            ],
        ], $extension->value);
    }

    #[Test]
    public function bothEvalInputsAreEncoded(): void
    {
        $first = 'first-salt';
        $second = 'second-salt';
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs($first, $second)
            ->build();

        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded($first),
                'second' => Base64UrlSafe::encodeUnpadded($second),
            ],
        ], $extension->value);
    }

    #[Test]
    public function withCredentialInputsKeyedByCredentialId(): void
    {
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A')
            ->withCredentialInputs('cred-B', 'salt-B', 'salt-B-2')
            ->build();

        static::assertSame([
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded('cred-A') => [
                    'first' => Base64UrlSafe::encodeUnpadded('salt-A'),
                ],
                Base64UrlSafe::encodeUnpadded('cred-B') => [
                    'first' => Base64UrlSafe::encodeUnpadded('salt-B'),
                    'second' => Base64UrlSafe::encodeUnpadded('salt-B-2'),
                ],
            ],
        ], $extension->value);
    }

    /**
     * The keys of the `evalByCredential` map must be the base64url encoding of the credential id, otherwise the client
     * rejects the ceremony with a SyntaxError. Credential ids are held in their raw binary form by a credential record,
     * so the builder is the one doing the encoding.
     */
    #[Test]
    public function aRawCredentialIdIsUsedAsABase64UrlEncodedKey(): void
    {
        $credentialId = hex2bin('0102030405060708090a0b0c0d0e0f10');

        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs($credentialId, 'first-salt')
            ->build();

        static::assertSame([
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded($credentialId) => [
                    'first' => Base64UrlSafe::encodeUnpadded('first-salt'),
                ],
            ],
        ], $extension->value);
    }

    #[Test]
    public function evalAndEvalByCredentialCanCoexist(): void
    {
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs('default-salt')
            ->withCredentialInputs('cred-A', 'specific-salt')
            ->build();

        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded('default-salt'),
            ],
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded('cred-A') => [
                    'first' => Base64UrlSafe::encodeUnpadded('specific-salt'),
                ],
            ],
        ], $extension->value);
    }

    #[Test]
    public function lastWriteWinsForRepeatedCalls(): void
    {
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs('first-salt')
            ->withInputs('replacement-salt', 'replacement-second')
            ->withCredentialInputs('cred', 'one')
            ->withCredentialInputs('cred', 'two')
            ->build();

        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded('replacement-salt'),
                'second' => Base64UrlSafe::encodeUnpadded('replacement-second'),
            ],
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded('cred') => [
                    'first' => Base64UrlSafe::encodeUnpadded('two'),
                ],
            ],
        ], $extension->value);
    }

    #[Test]
    public function singleCredentialEvalDoesNotRequireMultipleCredentialEvaluation(): void
    {
        $builder = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A');

        static::assertFalse($builder->requiresMultipleCredentialEvaluation());
    }

    #[Test]
    public function multipleCredentialEvalRequiresMultipleCredentialEvaluation(): void
    {
        $builder = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A')
            ->withCredentialInputs('cred-B', 'salt-B');

        static::assertTrue($builder->requiresMultipleCredentialEvaluation());
    }

    #[Test]
    public function repeatedCallsForSameCredentialDoNotInflateCount(): void
    {
        $builder = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A')
            ->withCredentialInputs('cred-A', 'replacement-salt');

        static::assertFalse($builder->requiresMultipleCredentialEvaluation());
    }

    #[Test]
    public function evalOnlyDoesNotRequireMultipleCredentialEvaluation(): void
    {
        $builder = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs('default-salt');

        static::assertFalse($builder->requiresMultipleCredentialEvaluation());
    }

    #[Test]
    public function deprecatedHmacSecretMcAliasStillReportsTheSameResult(): void
    {
        $single = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A');
        $multiple = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withCredentialInputs('cred-A', 'salt-A')
            ->withCredentialInputs('cred-B', 'salt-B');

        static::assertFalse($single->requiresHmacSecretMc());
        static::assertTrue($multiple->requiresHmacSecretMc());
    }

    #[Test]
    public function buildingWithoutAnyInputThrows(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('Cannot build a PRF extension without any input');

        PseudoRandomFunctionInputExtensionBuilder::create()->build();
    }

    #[Test]
    public function extensionSerializesToTheJsonShapeExpectedByTheBrowser(): void
    {
        $extension = PseudoRandomFunctionInputExtensionBuilder::create()
            ->withInputs('aaaa')
            ->withCredentialInputs('cred', 'bbbb', 'cccc')
            ->build();

        $json = $this->getSerializer()
            ->serialize($extension, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        static::assertJsonStringEqualsJsonString(
            '{"eval":{"first":"YWFhYQ"},"evalByCredential":{"Y3JlZA":{"first":"YmJiYg","second":"Y2NjYw"}}}',
            $json
        );
    }
}
