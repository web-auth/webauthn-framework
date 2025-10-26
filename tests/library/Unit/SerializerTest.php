<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Signal\AllAcceptedCredentials;
use Webauthn\Signal\CurrentUserDetails;
use Webauthn\Signal\UnknownCredential;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class SerializerTest extends AbstractTestCase
{
    public static function provideTrustPath(): iterable
    {
        yield [
            CertificateTrustPath::create(['X509_KEY_1', 'X509_KEY_2', 'X509_KEY_3']),
            '{"x5c":["X509_KEY_1","X509_KEY_2","X509_KEY_3"]}',
        ];
        yield [EmptyTrustPath::create(), '[]'];
    }

    #[Test]
    #[DataProvider('provideTrustPath')]
    public function theTrustPathCanBeSerialized(TrustPath $trustPath, string $expected): void
    {
        //When
        $json = $this->getSerializer()
            ->serialize(
                $trustPath,
                'json',
                [
                    JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                    AbstractObjectNormalizer::SKIP_UNINITIALIZED_VALUES => true,
                ],
            );

        //Then
        static::assertJsonStringEqualsJsonString($expected, $json);
    }

    #[Test]
    #[DataProvider('provideTrustPath')]
    public function theTrustPathCanBeDeserialized(TrustPath $trustPath, string $expected): void
    {
        //When
        $deserialized = $this->getSerializer()
            ->deserialize(
                $expected,
                TrustPath::class,
                'json',
                [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                    AbstractObjectNormalizer::SKIP_UNINITIALIZED_VALUES => true,
                ],
            );

        //Then
        static::assertEquals($trustPath, $deserialized);
    }

    #[Test]
    public function theCredentialCanBeDeserialized(): void
    {
        //Given
        $publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', 'example.com'),
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
                    "id": "example.com"
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
                "excludeCredentials": [],
                "attestation": "none"
            }',
            $json,
        );
    }

    #[Test]
    public function itSerializesSignalUnknownCredential(): void
    {
        $rp = new PublicKeyCredentialRpEntity('Example.com', 'rp.example.com');
        $credential = new PublicKeyCredentialDescriptor(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            'cred-123',
            []
        );
        $signal = new UnknownCredential($rp, $credential);

        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');
        static::assertJsonStringEqualsJsonString('{"rpId":"rp.example.com","credentialId":"Y3JlZC0xMjM"}', $json);
    }

    #[Test]
    public function itSerializesSignalAllAcceptedCredentials(): void
    {
        $rp = new PublicKeyCredentialRpEntity('Example.com', 'rp.example.com');
        $user = new PublicKeyCredentialUserEntity('john.doe', 'user-1', 'John Doe');
        $cred1 = new PublicKeyCredentialDescriptor(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            'cred-1',
            []
        );
        $cred2 = new PublicKeyCredentialDescriptor(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            'cred-2',
            []
        );
        $signal = new AllAcceptedCredentials($rp, $user, [$cred1, $cred2]);

        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');
        static::assertJsonStringEqualsJsonString(
            '{"rpId":"rp.example.com","userId":"dXNlci0x","allAcceptedCredentialIds":["Y3JlZC0x","Y3JlZC0y"]}',
            $json
        );
    }

    #[Test]
    public function itSerializesSignalCurrentUserDetails(): void
    {
        $rp = new PublicKeyCredentialRpEntity('Example.com', 'rp.example.com');
        $user = new PublicKeyCredentialUserEntity('john.doe', 'user-1', 'John Doe');
        $signal = new CurrentUserDetails($rp, $user);

        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');
        static::assertJsonStringEqualsJsonString(
            '{"rpId":"rp.example.com","userId":"dXNlci0x","name":"john.doe","displayName":"John Doe"}',
            $json
        );
    }
}
