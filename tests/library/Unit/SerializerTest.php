<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
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
                'signature' => 'MEUCIEY_vcNkbo_LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w_8RGiZzE-gOM61ffxmgEDeyhM=',
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTypeOtherThanPublicKey(): iterable
    {
        yield 'unknown type' => ['undefined'];
        yield 'type in upper case' => ['PUBLIC-KEY'];
        yield 'empty type' => [''];
    }

    #[Test]
    #[DataProvider('provideTypeOtherThanPublicKey')]
    public function publicKeyCredentialOfAnotherTypeIsRejected(string $type): void
    {
        // Given
        $data = self::assertionCredential();
        $data['type'] = $type;

        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid parameter "type". Shall be "public-key".');

        // When
        $this->getSerializer()
            ->deserialize(json_encode($data, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
    }

    #[Test]
    public function publicKeyCredentialOfTypePublicKeyIsDeserialized(): void
    {
        // Given
        $json = json_encode(self::assertionCredential(), JSON_THROW_ON_ERROR);

        // When
        $publicKeyCredential = $this->getSerializer()
            ->deserialize($json, PublicKeyCredential::class, 'json');

        // Then
        static::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $publicKeyCredential->type);
    }

    /**
     * The identifiers of the credential differ and its response is of no known kind: decoding them first would fail
     * with "Invalid ID" or "Unable to create the response object".
     */
    #[Test]
    public function publicKeyCredentialOfAnotherTypeIsRejectedBeforeItsMembersAreDecoded(): void
    {
        // Given
        $json = '{"id":"AAAA","rawId":"BBBB","type":"other","response":{}}';

        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid parameter "type". Shall be "public-key".');

        // When
        $this->getSerializer()
            ->deserialize($json, PublicKeyCredential::class, 'json');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAssertionResponseMemberThatIsNotBase64Url(): iterable
    {
        yield 'authenticatorData in standard base64' => [
            'authenticatorData',
            'FrAt+8PUzKN+vC9lFmWbEiENueEBirnxOpaQY46m/agFAAAAAg==',
        ];
        yield 'signature in standard base64' => [
            'signature',
            'eK5Yk9G8LjEsaEbK9Qq9Ovcx/Nf9xbRU5EURdMsiqJSQMpSCMHhcOBwfhPxx/zuPfYPxv/mRPgtPrX0vNQ3YAg==',
        ];
        yield 'userHandle in standard base64' => ['userHandle', '+/8='];
        yield 'signature with an incorrect padding' => ['signature', 'AA='];
        yield 'signature with a last character that completes no byte' => ['signature', 'AAAAA'];
        yield 'signature with pad bits that are not zero' => ['signature', 'AB'];
    }

    #[Test]
    #[DataProvider('provideAssertionResponseMemberThatIsNotBase64Url')]
    public function assertionResponseMemberThatIsNotBase64UrlIsRejected(string $member, string $value): void
    {
        // Given
        $data = self::assertionCredential();
        $data['response'][$member] = $value;

        // Then
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage(sprintf('Invalid parameter "%s". Shall be base64url encoded.', $member));

        // When
        $this->getSerializer()
            ->deserialize(json_encode($data, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAssertionResponseMemberInPaddedBase64Url(): iterable
    {
        yield 'authenticatorData' => ['authenticatorData', 'FrAt-8PUzKN-vC9lFmWbEiENueEBirnxOpaQY46m_agFAAAAAg=='];
        yield 'signature' => [
            'signature',
            'eK5Yk9G8LjEsaEbK9Qq9Ovcx_Nf9xbRU5EURdMsiqJSQMpSCMHhcOBwfhPxx_zuPfYPxv_mRPgtPrX0vNQ3YAg==',
        ];
        yield 'userHandle' => ['userHandle', '-_8='];
    }

    #[Test]
    #[DataProvider('provideAssertionResponseMemberInPaddedBase64Url')]
    public function assertionResponseMemberInPaddedBase64UrlIsDecodedAsWithoutPadding(
        string $member,
        string $value
    ): void {
        // Given
        $padded = self::assertionCredential();
        $padded['response'][$member] = $value;
        $unpadded = self::assertionCredential();
        $unpadded['response'][$member] = rtrim($value, '=');
        $serializer = $this->getSerializer();
        $expected = $serializer->deserialize(
            json_encode($unpadded, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json'
        );

        // When
        $publicKeyCredential = $serializer->deserialize(
            json_encode($padded, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json'
        );

        // Then
        static::assertEquals($expected, $publicKeyCredential);
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

    /**
     * The assertion of AssertionTest::previouslyFixedKeyCanBeVerified, whose binary members are base64url encoded
     * without padding.
     *
     * @return array{id: string, rawId: string, type: string, response: array<string, string>}
     */
    private static function assertionCredential(): array
    {
        return [
            'id' => '31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ',
            'rawId' => '31ivJEY3jmIoxWuGZ7pZjDuBW5n1PAMeG-e0drfhayCzOsuNaCG3PH43i-OebKT0jqY-bAFCEUh1JCCATSPa9N5QIUwwSlUQO9Pb5X1_yXJnY9q7GYfm3LvR4Yk6-HKj4MpBj6cbVOZyoLZQtd2lDEU7pSTcbTZBELQlODGSlbQ',
            'type' => 'public-key',
            'response' => [
                'authenticatorData' => 'FrAt-8PUzKN-vC9lFmWbEiENueEBirnxOpaQY46m_agFAAAAAg',
                'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiIyTVNuOTE2eFBhYU9jcDg2c1NZQlZzcVl6Uk9pNFk4SDdCcmxfOEQ1RHJjIiwib3JpZ2luIjoiaHR0cHM6Ly90dWxlYXAtd2ViLnR1bGVhcC1haW8tZGV2LmRvY2tlciIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                'signature' => 'eK5Yk9G8LjEsaEbK9Qq9Ovcx_Nf9xbRU5EURdMsiqJSQMpSCMHhcOBwfhPxx_zuPfYPxv_mRPgtPrX0vNQ3YAg',
            ],
        ];
    }
}
