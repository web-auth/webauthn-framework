<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\CollectedClientData;

/**
 * @internal
 */
final class CollectedClientDataTest extends TestCase
{
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

    /**
     * The tokenBinding member is [RESERVED] since Webauthn Level 3. It is never read by the Relying Party, so whatever
     * a client puts under that key must not fail the ceremony.
     */
    #[Test]
    public function aReservedTokenBindingMemberIsNotValidated(): void
    {
        // Given
        $data = [
            'type' => 'type',
            'origin' => 'origin',
            'challenge' => Base64UrlSafe::encodeUnpadded('challenge'),
            'tokenBinding' => 'supported',
        ];

        // When
        $collectedClientData = CollectedClientData::create('raw_data', $data);

        // Then
        static::assertSame('supported', $collectedClientData->get('tokenBinding'));
    }
}
