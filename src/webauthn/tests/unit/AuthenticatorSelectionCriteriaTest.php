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
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AuthenticatorSelectionCriteria
 */
class AuthenticatorSelectionCriteriaTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria('authenticator_attachment', true, 'user_verification');

        static::assertEquals('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertEquals('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertEquals('{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}', json_encode($authenticatorSelectionCriteria));

        $data = AuthenticatorSelectionCriteria::createFromString('{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}');
        static::assertEquals('user_verification', $data->getUserVerification());
        static::assertEquals('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertTrue($data->isRequireResidentKey());
        static::assertEquals('{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}', json_encode($data));
    }
}
