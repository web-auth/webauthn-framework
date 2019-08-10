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
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CollectedClientData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AuthenticatorAttestationResponse
 */
class AuthenticatorAttestationResponseTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAttestationResponseCanBeCreatedAndValueAccessed(): void
    {
        $clientDataJSON = $this->prophesize(CollectedClientData::class);
        $attestationObject = $this->prophesize(AttestationObject::class);

        $authenticatorAttestationResponse = new AuthenticatorAttestationResponse(
            $clientDataJSON->reveal(),
            $attestationObject->reveal()
        );

        static::assertInstanceOf(CollectedClientData::class, $authenticatorAttestationResponse->getClientDataJSON());
        static::assertInstanceOf(AttestationObject::class, $authenticatorAttestationResponse->getAttestationObject());
    }
}
