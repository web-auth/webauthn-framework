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
        // Given
        $expectedJson = '{"requireResidentKey":false,"userVerification":"required","residentKey":"preferred","authenticatorAttachment":"platform"}';
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
            false
        );

        //When
        $data = AuthenticatorSelectionCriteria::createFromString($expectedJson);

        //Then
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $data->userVerification
        );
        static::assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            $data->authenticatorAttachment
        );
        static::assertFalse($data->requireResidentKey);
        static::assertSame(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED, $data->residentKey);
        static::assertSame($expectedJson, json_encode($data, JSON_THROW_ON_ERROR));
        static::assertSame($expectedJson, json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        // Given
        $expectedJson = '{"requireResidentKey":true,"userVerification":"required","residentKey":"required","authenticatorAttachment":"platform"}';
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            true
        );

        //When
        $data = AuthenticatorSelectionCriteria::createFromString($expectedJson);

        //Then
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $data->userVerification
        );
        static::assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            $data->authenticatorAttachment
        );
        static::assertTrue($data->requireResidentKey);
        static::assertSame(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED, $data->residentKey);
        static::assertSame($expectedJson, json_encode($data, JSON_THROW_ON_ERROR));
        static::assertSame($expectedJson, json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR));
    }
}
