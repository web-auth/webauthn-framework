<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class SerializerTest extends AbstractTestCase
{
    #[Test]
    public function theCredentialCanBeDeserialized(): void
    {
        //Given
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Example.com', 'example.com'),
            PublicKeyCredentialUserEntity::create('john.doe', '0123456789', 'John Doe'),
            hash('xxh128', 'pk id test', true),
            [PublicKeyCredentialParameters::createPk(-1), PublicKeyCredentialParameters::createPk(256)],
            AuthenticatorSelectionCriteria::create(
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        );

        //When
        $json = $this->getSerializer()
            ->serialize(
                $publicKeyCredentialCreationOptions,
                'json',
                [
                    JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                    AbstractObjectNormalizer::SKIP_UNINITIALIZED_VALUES => true,
                ],
            );

        //Then
        static::assertJsonStringEqualsJsonString(
            '{
                "rp": {
                    "id": "example.com",
                    "name": "Example.com"
                },
                "user": {
                    "id": "MDEyMzQ1Njc4OQ",
                    "name": "john.doe",
                    "displayName": "John Doe"
                },
                "challenge": "Q3_A7bKkpBKqDwV0fdS4Ow",
                "pubKeyCredParams": [
                    {
                        "type": "public-key",
                        "alg": -1
                    },
                    {
                        "type": "public-key",
                        "alg": 256
                    }
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "required"
                },
                "attestation": "none"
            }',
            $json,
        );
    }
}
