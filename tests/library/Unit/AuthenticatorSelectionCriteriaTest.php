<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AuthenticatorSelectionCriteriaTest extends AbstractTestCase
{
    #[Test]
    public function anAuthenticatorSelectionCriteriaCanBeCreatedAndValueAccessed(): void
    {
        // Given
        $expectedJson = '{"userVerification":"required","authenticatorAttachment":"platform"}';
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE
        );

        //When
        $data = $this->getSerializer()
            ->deserialize($expectedJson, AuthenticatorSelectionCriteria::class, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        //Then
        static::assertSame(
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            $data->userVerification
        );
        static::assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            $data->authenticatorAttachment
        );
        static::assertNull($data->requireResidentKey);
        static::assertSame(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE, $data->residentKey);
        static::assertJsonStringEqualsJsonString($expectedJson, $this->getSerializer()->serialize($data, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
        static::assertJsonStringEqualsJsonString(
            $expectedJson,
            $this->getSerializer()
                ->serialize($authenticatorSelectionCriteria, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }

    #[Test]
    public function anAuthenticatorSelectionCriteriaWithResidentKeyCanBeCreatedAndValueAccessed(): void
    {
        // Given
        $expectedJson = '{"authenticatorAttachment":"platform","requireResidentKey":true,"userVerification":"required","residentKey":"required"}';
        $authenticatorSelectionCriteria = AuthenticatorSelectionCriteria::create(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            true
        );

        //When
        $data = $this->getSerializer()
            ->deserialize($expectedJson, AuthenticatorSelectionCriteria::class, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

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
        static::assertSame($expectedJson, $this->getSerializer()->serialize($data, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
        static::assertSame($expectedJson, $this->getSerializer()->serialize($authenticatorSelectionCriteria, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }
}
