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
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment('authenticator_attachment')
            ->setRequireResidentKey(true)
            ->setUserVerification('user_verification')
        ;

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertNull($authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertTrue($data->isRequireResidentKey());
        static::assertNull($data->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data)
        );
    }

    /**
     * @test
     */
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment('authenticator_attachment')
            ->setRequireResidentKey(true)
            ->setUserVerification('user_verification')
            ->setResidentKey('resident_key')
        ;

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertSame('resident_key', $authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"resident_key"}',
            json_encode($authenticatorSelectionCriteria)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"resident_key"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertTrue($data->isRequireResidentKey());
        static::assertSame('resident_key', $data->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"resident_key"}',
            json_encode($data)
        );
    }
}
