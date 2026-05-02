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
                'cred-A' => [
                    'first' => Base64UrlSafe::encodeUnpadded('salt-A'),
                ],
                'cred-B' => [
                    'first' => Base64UrlSafe::encodeUnpadded('salt-B'),
                    'second' => Base64UrlSafe::encodeUnpadded('salt-B-2'),
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
                'cred-A' => [
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
                'cred' => [
                    'first' => Base64UrlSafe::encodeUnpadded('two'),
                ],
            ],
        ], $extension->value);
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
            '{"eval":{"first":"YWFhYQ"},"evalByCredential":{"cred":{"first":"YmJiYg","second":"Y2NjYw"}}}',
            $json
        );
    }
}
