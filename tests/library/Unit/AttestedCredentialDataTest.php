<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestedCredentialData;
use const JSON_UNESCAPED_SLASHES;

/**
 * @internal
 */
final class AttestedCredentialDataTest extends TestCase
{
    #[Test]
    #[DataProvider('dataAAGUID')]
    public function anAttestedCredentialDataCanBeCreatedAndValueAccessed(string $uuid): void
    {
        // Given
        $attestedCredentialData = AttestedCredentialData::create(
            Uuid::fromString($uuid),
            'credential_id',
            'credential_public_key'
        );

        // Then
        static::assertSame($uuid, $attestedCredentialData->aaguid->__toString());
        static::assertSame('credential_id', $attestedCredentialData->credentialId);
        static::assertSame('credential_public_key', $attestedCredentialData->credentialPublicKey);
        static::assertSame(
            sprintf(
                '{"aaguid":"%s","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}',
                $uuid
            ),
            json_encode($attestedCredentialData, JSON_UNESCAPED_SLASHES)
        );
    }

    public static function dataAAGUID(): iterable
    {
        yield [
            'uuid' => '00000000-0000-0000-0000-000000000000',
        ];
        yield [
            'uuid' => '6028b017-b1d4-4c02-b4b3-afcdafc96bb2',
        ];
        yield [
            'uuid' => 'b93fd961-f2e6-462f-b122-82002247de78',
        ];
        yield [
            'uuid' => '454e5346-4944-4ffd-6c93-8e9267193e9a',
        ];
        yield [
            'uuid' => 'adce0002-35bc-c60a-648b-0b25f1f05503',
        ];
        yield [
            'uuid' => '77010bd7-212a-4fc9-b236-d2ca5e9d4084',
        ];
        yield [
            'uuid' => '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73',
        ];
        yield [
            'uuid' => 'fa2b99dc-9e39-4257-8f92-4a30d23c4118',
        ];
    }
}
