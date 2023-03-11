<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaTest extends TestCase
{
    #[Test]
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment('authenticator_attachment')
            ->setResidentKey(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED)
            ->setUserVerification('user_verification')
            ->setRequireResidentKey(true)
        ;

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertSame('required', $authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertTrue($data->isRequireResidentKey());
        static::assertSame('required', $data->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }

    #[Test]
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment('authenticator_attachment')
            ->setResidentKey(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED)
            ->setUserVerification('user_verification')
            ->setRequireResidentKey(true);

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertSame('required', $authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"required"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertTrue($data->isRequireResidentKey());
        static::assertSame('required', $data->getResidentKey());
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
