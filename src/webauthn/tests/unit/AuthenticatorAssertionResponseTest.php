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
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CollectedClientData;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AuthenticatorAssertionResponse
 */
class AuthenticatorAssertionResponseTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorAssertionResponseCanBeCreatedAndValueAccessed(): void
    {
        $clientDataJSON = $this->prophesize(CollectedClientData::class);
        $authenticatorData = $this->prophesize(AuthenticatorData::class);

        $authenticatorAssertionResponse = new AuthenticatorAssertionResponse(
            $clientDataJSON->reveal(),
            $authenticatorData->reveal(),
            'signature',
            base64_encode('user_handle')
        );

        static::assertInstanceOf(CollectedClientData::class, $authenticatorAssertionResponse->getClientDataJSON());
        static::assertInstanceOf(AuthenticatorData::class, $authenticatorAssertionResponse->getAuthenticatorData());
        static::assertEquals('signature', $authenticatorAssertionResponse->getSignature());
        static::assertEquals('user_handle', $authenticatorAssertionResponse->getUserHandle());
    }
}
