<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\InvalidDataException;
use Webauthn\MetadataService\Statement\MetadataStatement;
use Webauthn\PublicKeyCredential;
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
    public function trustPathCanBeSerialized(TrustPath $trustPath, string $expected): void
    {
        // Given
        // TrustPath provided by data provider

        // When
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

        // Then
        static::assertJsonStringEqualsJsonString($expected, $json);
    }

    #[Test]
    #[DataProvider('provideTrustPath')]
    public function trustPathCanBeDeserialized(TrustPath $trustPath, string $expected): void
    {
        // Given
        // TrustPath provided by data provider

        // When
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

        // Then
        static::assertEquals($trustPath, $deserialized);
    }

    public static function providePublicKeyCredentialMember(): iterable
    {
        yield ['id'];
        yield ['rawId'];
        yield ['type'];
        yield ['response'];
    }

    #[Test]
    #[DataProvider('providePublicKeyCredentialMember')]
    public function publicKeyCredentialWithAMissingMemberIsRejected(string $member): void
    {
        // Given
        $data = [
            'id' => 'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'type' => 'public-key',
            'rawId' => 'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
            'response' => [
                'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew',
                'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                'signature' => 'MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=',
                'userHandle' => null,
            ],
        ];
        unset($data[$member]);

        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Missing ' . $member);

        // When
        $this->getSerializer()
            ->deserialize(json_encode($data, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
    }

    #[Test]
    public function credentialCanBeSerializedAndDeserialized(): void
    {
        // Given
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

        // When
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

        // Then
        static::assertJsonStringEqualsJsonString(
            '{
                "rp": {
                    "id": "example.com",
                    "name": "example.com"
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
    public function signalUnknownCredentialCanBeSerialized(): void
    {
        // Given
        $rp = new PublicKeyCredentialRpEntity('Example.com', 'rp.example.com');
        $credential = new PublicKeyCredentialDescriptor(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            'cred-123',
            []
        );
        $signal = new UnknownCredential($rp, $credential);

        // When
        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');

        // Then
        static::assertJsonStringEqualsJsonString('{"rpId":"rp.example.com","credentialId":"Y3JlZC0xMjM"}', $json);
    }

    #[Test]
    public function signalAllAcceptedCredentialsCanBeSerialized(): void
    {
        // Given
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

        // When
        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"rpId":"rp.example.com","userId":"dXNlci0x","allAcceptedCredentialIds":["Y3JlZC0x","Y3JlZC0y"]}',
            $json
        );
    }

    #[Test]
    public function signalCurrentUserDetailsCanBeSerialized(): void
    {
        // Given
        $rp = new PublicKeyCredentialRpEntity('Example.com', 'rp.example.com');
        $user = new PublicKeyCredentialUserEntity('john.doe', 'user-1', 'John Doe');
        $signal = new CurrentUserDetails($rp, $user);

        // When
        $serializer = $this->getSerializer();
        $json = $serializer->serialize($signal, 'json');

        // Then
        static::assertJsonStringEqualsJsonString(
            '{"rpId":"rp.example.com","userId":"dXNlci0x","name":"john.doe","displayName":"John Doe"}',
            $json
        );
    }

    #[Test]
    public function metadataStatementWithoutUserVerificationDetailsCanBeDeserialized(): void
    {
        // Given
        $json = '{"description":"Authenticator","authenticatorVersion":1,"protocolFamily":"fido2","schema":3,"upv":[{"major":1,"minor":0}],"authenticationAlgorithms":["secp256r1_ecdsa_sha256_raw"],"publicKeyAlgAndEncodings":["cose"],"attestationTypes":["none"],"matcherProtection":["software"],"tcDisplay":[],"attestationRootCertificates":[]}';

        // When
        $statement = $this->getSerializer()
            ->deserialize($json, MetadataStatement::class, 'json');

        // Then
        static::assertSame([], $statement->userVerificationDetails);
    }
}
