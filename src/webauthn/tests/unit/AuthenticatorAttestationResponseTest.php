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

use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CollectedClientData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AuthenticatorAttestationResponse
 *
 * @internal
 */
class AuthenticatorAttestationResponseTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAttestationResponseCanBeCreatedAndValueAccessed(): void
    {
        $clientDataJSON = $this->createMock(CollectedClientData::class);
        $attestationObject = $this->createMock(AttestationObject::class);

        $authenticatorAttestationResponse = new AuthenticatorAttestationResponse(
            $clientDataJSON,
            $attestationObject
        );

        static::assertInstanceOf(CollectedClientData::class, $authenticatorAttestationResponse->getClientDataJSON());
        static::assertInstanceOf(AttestationObject::class, $authenticatorAttestationResponse->getAttestationObject());
    }
}
