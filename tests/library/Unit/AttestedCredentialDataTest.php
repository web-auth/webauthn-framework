<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit;

use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;
use Webauthn\AttestedCredentialData;

/**
 * @internal
 */
final class AttestedCredentialDataTest extends TestCase
{
    /**
     * @test
     * @dataProvider dataAAGUID
     */
    public function anAttestedCredentialDataCanBeCreatedAndValueAccessed(string $uuid): void
    {
        $attestedCredentialData = new AttestedCredentialData(Uuid::fromString(
            $uuid
        ), 'credential_id', 'credential_public_key');

        static::assertSame($uuid, $attestedCredentialData->getAaguid()->toString());
        static::assertSame($uuid, $attestedCredentialData->getAaguid()->toString());
        static::assertSame('credential_id', $attestedCredentialData->getCredentialId());
        static::assertSame('credential_public_key', $attestedCredentialData->getCredentialPublicKey());
        static::assertSame(
            '{"aaguid":"' . $uuid . '","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}',
            json_encode($attestedCredentialData, JSON_UNESCAPED_SLASHES)
        );

        $json = json_decode(
            '{"aaguid":"' . $uuid . '","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}',
            true
        );
    }

    public function dataAAGUID(): array
    {
        return [
            [
                'uuid' => '00000000-0000-0000-0000-000000000000',
            ], [
                'uuid' => '6028b017-b1d4-4c02-b4b3-afcdafc96bb2',
            ], [
                'uuid' => 'b93fd961-f2e6-462f-b122-82002247de78',
            ], [
                'uuid' => '454e5346-4944-4ffd-6c93-8e9267193e9a',
            ], [
                'uuid' => 'adce0002-35bc-c60a-648b-0b25f1f05503',
            ], [
                'uuid' => '77010bd7-212a-4fc9-b236-d2ca5e9d4084',
            ], [
                'uuid' => '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73',
            ], [
                'uuid' => 'fa2b99dc-9e39-4257-8f92-4a30d23c4118',
            ],
        ];
    }
}
