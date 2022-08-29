<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
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
            ->setResidentKey(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED)
            ->setUserVerification('user_verification');

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertSame('required', $authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            // '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}', // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertFalse($data->isRequireResidentKey());
        static::assertSame('preferred', $data->getResidentKey());
        static::assertSame(
            // '{"requireResidentKey":false,"userVerification":"user_verification","residentKey":"preferred","authenticatorAttachment":"authenticator_attachment"}', // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
            '{"requireResidentKey":false,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }

    /**
     * @test
     */
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create()
            ->setAuthenticatorAttachment('authenticator_attachment')
            ->setResidentKey(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED)
            ->setUserVerification('user_verification');

        static::assertSame('user_verification', $authenticatorSelectionCriteria->getUserVerification());
        static::assertSame('authenticator_attachment', $authenticatorSelectionCriteria->getAuthenticatorAttachment());
        static::assertTrue($authenticatorSelectionCriteria->isRequireResidentKey());
        static::assertSame('required', $authenticatorSelectionCriteria->getResidentKey());
        static::assertSame(
            // '{"requireResidentKey":true,"userVerification":"user_verification","residentKey":"required","authenticatorAttachment":"authenticator_attachment"}', // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($authenticatorSelectionCriteria, JSON_THROW_ON_ERROR)
        );

        $data = AuthenticatorSelectionCriteria::createFromString(
            '{"requireResidentKey":true,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment","residentKey":"resident_key"}'
        );
        static::assertSame('user_verification', $data->getUserVerification());
        static::assertSame('authenticator_attachment', $data->getAuthenticatorAttachment());
        static::assertFalse($data->isRequireResidentKey());
        static::assertSame('resident_key', $data->getResidentKey());
        static::assertSame(
            // '{"requireResidentKey":false,"userVerification":"user_verification","residentKey":"resident_key","authenticatorAttachment":"authenticator_attachment"}', // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
            '{"requireResidentKey":false,"userVerification":"user_verification","authenticatorAttachment":"authenticator_attachment"}',
            json_encode($data, JSON_THROW_ON_ERROR)
        );
    }
}
