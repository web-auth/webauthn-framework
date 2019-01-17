<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\AttestedCredentialData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AttestedCredentialData
 */
class AttestedCredentialDataTest extends TestCase
{
    /**
     * @test
     */
    public function anAttestedCredentialDataCanBeCreatedAndValueAccessed(): void
    {
        $attestedCredentialData = new AttestedCredentialData('aauid', 'credential_id', 'credential_public_key');

        static::assertEquals('aauid', $attestedCredentialData->getAaguid());
        static::assertEquals('credential_id', $attestedCredentialData->getCredentialId());
        static::assertEquals('credential_public_key', $attestedCredentialData->getCredentialPublicKey());
        static::assertEquals('{"aaguid":"YWF1aWQ=","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}', \Safe\json_encode($attestedCredentialData));

        $json = \Safe\json_decode('{"aaguid":"YWF1aWQ=","credentialId":"Y3JlZGVudGlhbF9pZA==","credentialPublicKey":"Y3JlZGVudGlhbF9wdWJsaWNfa2V5"}', true);
        $created = AttestedCredentialData::createFromJson($json);
        static::assertEquals($attestedCredentialData, $created);
    }
}
