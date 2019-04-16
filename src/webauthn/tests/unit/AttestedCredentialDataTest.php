<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use function Safe\json_decode;
use function Safe\json_encode;
use Webauthn\AttestedCredentialData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \AttestedCredentialData
 */
class AttestedCredentialDataTest extends TestCase
{
    /**
     * @test
     * @dataProvider dataAAGUID
     */
    public function anAttestedCredentialDataCanBeCreatedAndValueAccessed(string $b64, string $uuid): void
    {
        $attestedCredentialData = new AttestedCredentialData(base64_decode($b64, true), 'credential_id', 'credential_public_key');

        static::assertEquals(base64_decode($b64, true), $attestedCredentialData->getAaguid());
        static::assertEquals($uuid, $attestedCredentialData->getAaguidAsUuid());
        static::assertEquals('credential_id', $attestedCredentialData->getCredentialId());
        static::assertEquals('credential_public_key', $attestedCredentialData->getCredentialPublicKey());
        static::assertEquals('{"aaguid":"'.$b64.'","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}', json_encode($attestedCredentialData, JSON_UNESCAPED_SLASHES));

        $json = json_decode('{"aaguid":"'.$b64.'","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}', true);
        $created = AttestedCredentialData::createFromArray($json);
        static::assertEquals($attestedCredentialData, $created);
    }

    public function dataAAGUID(): array
    {
        return [
            [
                'b64' => 'AAAAAAAAAAAAAAAAAAAAAA==',
                'uuid' => '00000000-0000-0000-0000-000000000000',
            ], [
                'b64' => 'YCiwF7HUTAK0s6/Nr8lrsg==',
                'uuid' => '6028b017-b1d4-4c02-b4b3-afcdafc96bb2',
            ], [
                'b64' => 'uT/ZYfLmRi+xIoIAIkfeeA==',
                'uuid' => 'b93fd961-f2e6-462f-b122-82002247de78',
            ], [
                'b64' => 'RU5TRklET/1sk46SZxk+mg==',
                'uuid' => '454e5346-4944-4ffd-6c93-8e9267193e9a',
            ], [
                'b64' => 'rc4AAjW8xgpkiwsl8fBVAw==',
                'uuid' => 'adce0002-35bc-c60a-648b-0b25f1f05503',
            ], [
                'b64' => 'dwEL1yEqT8myNtLKXp1AhA==',
                'uuid' => '77010bd7-212a-4fc9-b236-d2ca5e9d4084',
            ], [
                'b64' => 'bUS6m/bsLkm5MAyP6SDLcw==',
                'uuid' => '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73',
            ], [
                'b64' => '+iuZ3J45QlePkkow0jxBGA==',
                'uuid' => 'fa2b99dc-9e39-4257-8f92-4a30d23c4118',
            ],
        ];
    }
}
