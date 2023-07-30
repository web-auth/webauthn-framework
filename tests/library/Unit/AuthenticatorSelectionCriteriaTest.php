<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticatorSelectionCriteria;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaTest extends TestCase
{
    #[Test]
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            'authenticator_attachment',
            'user_verification',
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            true
        );

        static::assertSame('user_verification', $authenticatorSelectionCriteria->userVerification);
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->authenticatorAttachment);
        static::assertTrue($authenticatorSelectionCriteria->requireResidentKey);
        static::assertSame('required', $authenticatorSelectionCriteria->residentKey);
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}'
        );
        static::assertSame('user_verification', $data->userVerification);
        static::assertSame('authenticator_attachment', $data->authenticatorAttachment);
        static::assertTrue($data->requireResidentKey);
        static::assertSame('required', $data->residentKey);
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }

    #[Test]
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            'authenticator_attachment',
            'user_verification',
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            true
        );

        static::assertSame('user_verification', $authenticatorSelectionCriteria->userVerification);
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->authenticatorAttachment);
        static::assertTrue($authenticatorSelectionCriteria->requireResidentKey);
        static::assertSame('required', $authenticatorSelectionCriteria->residentKey);
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"required"}'
        );
        static::assertSame('user_verification', $data->userVerification);
        static::assertSame('authenticator_attachment', $data->authenticatorAttachment);
        static::assertTrue($data->requireResidentKey);
        static::assertSame('required', $data->residentKey);
        static::assertSame(
            '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
