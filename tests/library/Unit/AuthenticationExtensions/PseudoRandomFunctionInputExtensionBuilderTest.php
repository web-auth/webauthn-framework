<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtensionBuilder;

/**
 * @internal
 */
final class PseudoRandomFunctionInputExtensionBuilderTest extends TestCase
{
    #[Test]
    public function theInputsAreBase64UrlEncoded(): void
    {
        // Given
        $builder = PseudoRandomFunctionInputExtensionBuilder::create();

        // When
        $extension = $builder->withInputs('first-salt', 'second-salt')
            ->build();

        // Then
        static::assertSame('prf', $extension->name);
        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded('first-salt'),
                'second' => Base64UrlSafe::encodeUnpadded('second-salt'),
            ],
        ], $extension->value);
    }

    #[Test]
    public function theSecondInputIsOmittedWhenNotProvided(): void
    {
        // Given
        $builder = PseudoRandomFunctionInputExtensionBuilder::create();

        // When
        $extension = $builder->withInputs('first-salt')
            ->build();

        // Then
        static::assertSame([
            'eval' => [
                'first' => Base64UrlSafe::encodeUnpadded('first-salt'),
            ],
        ], $extension->value);
    }

    /**
     * The keys of the "evalByCredential" map must be the base64url encoding of the credential ID, otherwise the client
     * rejects the ceremony with a SyntaxError.
     */
    #[Test]
    public function theCredentialIdIsUsedAsABase64UrlEncodedKey(): void
    {
        // Given
        $credentialId = hex2bin('0102030405060708090a0b0c0d0e0f10');
        $builder = PseudoRandomFunctionInputExtensionBuilder::create();

        // When
        $extension = $builder->withCredentialInputs($credentialId, 'first-salt')
            ->build();

        // Then
        static::assertSame([
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded($credentialId) => [
                    'first' => Base64UrlSafe::encodeUnpadded('first-salt'),
                ],
            ],
        ], $extension->value);
    }

    #[Test]
    public function severalCredentialsCanBeEvaluated(): void
    {
        // Given
        $firstCredentialId = hex2bin('aabb');
        $secondCredentialId = hex2bin('ccdd');
        $builder = PseudoRandomFunctionInputExtensionBuilder::create();

        // When
        $extension = $builder->withCredentialInputs($firstCredentialId, 'first-salt')
            ->withCredentialInputs($secondCredentialId, 'other-salt', 'second-salt')
            ->build();

        // Then
        static::assertSame([
            'evalByCredential' => [
                Base64UrlSafe::encodeUnpadded($firstCredentialId) => [
                    'first' => Base64UrlSafe::encodeUnpadded('first-salt'),
                ],
                Base64UrlSafe::encodeUnpadded($secondCredentialId) => [
                    'first' => Base64UrlSafe::encodeUnpadded('other-salt'),
                    'second' => Base64UrlSafe::encodeUnpadded('second-salt'),
                ],
            ],
        ], $extension->value);
    }
}
