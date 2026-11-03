<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\CollectedClientData;
use Webauthn\Exception\InvalidDataException;

/**
 * @internal
 */
final class CollectedClientDataTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function tokenBindingDictionaries(): iterable
    {
        yield 'status "supported"' => [[
            'status' => 'supported',
        ]];
        yield 'status "not-supported"' => [[
            'status' => 'not-supported',
        ]];
        yield 'status "present" with the Token Binding ID' => [[
            'status' => 'present',
            'id' => Base64UrlSafe::encodeUnpadded('id'),
        ]];
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function tokenBindingsThatAreNotObjects(): iterable
    {
        yield 'string' => ['supported'];
        yield 'number' => [1];
        yield 'boolean' => [true];
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function tokenBindingsWithoutAKnownStatus(): iterable
    {
        yield 'missing status' => [[
            'id' => Base64UrlSafe::encodeUnpadded('id'),
        ]];
        yield 'unknown status' => [[
            'status' => 'unknown',
        ]];
        yield 'status that is not a string' => [[
            'status' => true,
        ]];
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function presentTokenBindingsWithoutTheirId(): iterable
    {
        yield 'missing id' => [[
            'status' => 'present',
        ]];
        yield 'empty id' => [[
            'status' => 'present',
            'id' => '',
        ]];
        yield 'id that is not a string' => [[
            'status' => 'present',
            'id' => 1,
        ]];
    }

    #[Test]
    public function collectedClientDataCanBeCreatedAndValuesAccessed(): void
    {
        // Given
        $collectedClientData = CollectedClientData::create(
            'raw_data',
            [
                'type' => 'type',
                'origin' => 'origin',
                'crossOrigin' => true,
                'challenge' => Base64UrlSafe::encodeUnpadded('challenge'),
                'extensions' => 'extensions',
                'tokenBinding' => [
                    'status' => 'present',
                    'id' => Base64UrlSafe::encodeUnpadded('id'),
                ],
            ]
        );

        // When
        $allKeys = $collectedClientData->all();

        // Then
        static::assertSame('raw_data', $collectedClientData->rawData);
        static::assertSame('origin', $collectedClientData->origin);
        static::assertTrue($collectedClientData->crossOrigin);
        static::assertSame('challenge', $collectedClientData->challenge);
        static::assertSame('type', $collectedClientData->type);
        static::assertSame(['type', 'origin', 'crossOrigin', 'challenge', 'extensions', 'tokenBinding'], $allKeys);
        static::assertTrue($collectedClientData->has('extensions'));
        static::assertSame('extensions', $collectedClientData->get('extensions'));
    }

    #[Test]
    public function clientDataWithoutTokenBindingIsAccepted(): void
    {
        $collectedClientData = CollectedClientData::create('raw_data', [
            'type' => 'type',
            'origin' => 'origin',
            'challenge' => Base64UrlSafe::encodeUnpadded('challenge'),
        ]);

        static::assertFalse($collectedClientData->has('tokenBinding'));
    }

    #[Test]
    public function aNullTokenBindingIsHandledAsAMissingOne(): void
    {
        $collectedClientData = CollectedClientData::create('raw_data', self::clientDataWithTokenBinding(null));

        static::assertNull($collectedClientData->get('tokenBinding'));
    }

    /**
     * The tokenBinding member is [RESERVED] since Webauthn Level 3, which still defines the TokenBinding dictionary it
     * holds (section 5.8.1). A client that sends the member sends that dictionary.
     *
     * @param array<string, string> $tokenBinding
     */
    #[Test]
    #[DataProvider('tokenBindingDictionaries')]
    public function aTokenBindingDictionaryIsAccepted(array $tokenBinding): void
    {
        $collectedClientData = CollectedClientData::create(
            'raw_data',
            self::clientDataWithTokenBinding($tokenBinding)
        );

        static::assertSame($tokenBinding, $collectedClientData->get('tokenBinding'));
    }

    /**
     * F-15 of the FIDO Conformance Tools, in Server-ServerAuthenticatorAttestationResponse-Resp-2 and
     * Server-ServerAuthenticatorAssertionResponse-Resp-2.
     */
    #[Test]
    #[DataProvider('tokenBindingsThatAreNotObjects')]
    public function aTokenBindingThatIsNotAnObjectIsRejected(mixed $tokenBinding): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid parameter "tokenBinding". Shall be an object.');

        CollectedClientData::create('raw_data', self::clientDataWithTokenBinding($tokenBinding));
    }

    /**
     * F-16 and F-17 of the FIDO Conformance Tools, in Server-ServerAuthenticatorAttestationResponse-Resp-2 and
     * Server-ServerAuthenticatorAssertionResponse-Resp-2.
     *
     * @param array<string, mixed> $tokenBinding
     */
    #[Test]
    #[DataProvider('tokenBindingsWithoutAKnownStatus')]
    public function aTokenBindingWithoutAKnownStatusIsRejected(array $tokenBinding): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(
            'Invalid parameter "tokenBinding.status". Shall be "present", "supported" or "not-supported".'
        );

        CollectedClientData::create('raw_data', self::clientDataWithTokenBinding($tokenBinding));
    }

    /**
     * @param array<string, mixed> $tokenBinding
     */
    #[Test]
    #[DataProvider('presentTokenBindingsWithoutTheirId')]
    public function aPresentTokenBindingWithoutItsIdIsRejected(array $tokenBinding): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(
            'Invalid parameter "tokenBinding.id". Shall be a non-empty string when the status is "present".'
        );

        CollectedClientData::create('raw_data', self::clientDataWithTokenBinding($tokenBinding));
    }

    /**
     * @return array<string, mixed>
     */
    private static function clientDataWithTokenBinding(mixed $tokenBinding): array
    {
        return [
            'type' => 'type',
            'origin' => 'origin',
            'challenge' => Base64UrlSafe::encodeUnpadded('challenge'),
            'tokenBinding' => $tokenBinding,
        ];
    }
}
