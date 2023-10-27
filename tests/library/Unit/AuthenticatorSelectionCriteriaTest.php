<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Tests\AbstractTestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaTest extends AbstractTestCase
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
        $data = $this->getSerializer()
            ->deserialize($expectedJson, AuthenticatorSelectionCriteria::class, 'json');

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
        $data = $this->getSerializer()
            ->deserialize($expectedJson, AuthenticatorSelectionCriteria::class, 'json');

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
