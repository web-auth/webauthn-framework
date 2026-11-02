<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckClientDataCollectorType;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * The type of the client data names the ceremony it was collected for: "webauthn.create" for a registration and
 * "webauthn.get" for an authentication (Webauthn Level 3, sections 7.1 and 7.2). With the collector it uses by
 * default, the step accepts the type of the ceremony the options were created for, and no other.
 *
 * @internal
 */
final class CheckClientDataCollectorTypeTest extends AbstractTestCase
{
    /**
     * @return iterable<string, array{PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions, AuthenticatorAttestationResponse|AuthenticatorAssertionResponse}>
     */
    public static function provideResponseWithTheTypeOfTheCeremony(): iterable
    {
        yield 'registration' => [self::creationOptions(), self::attestationResponse('webauthn.create')];
        yield 'authentication' => [self::requestOptions(), self::assertionResponse('webauthn.get')];
    }

    /**
     * @return iterable<string, array{PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions, AuthenticatorAttestationResponse|AuthenticatorAssertionResponse, string}>
     */
    public static function provideResponseWithTheTypeOfTheOtherCeremony(): iterable
    {
        yield 'registration with the type of an authentication' => [
            self::creationOptions(),
            self::attestationResponse('webauthn.get'),
            'The client data type is not "webauthn.create".',
        ];
        yield 'authentication with the type of a registration' => [
            self::requestOptions(),
            self::assertionResponse('webauthn.create'),
            'The client data type is not "webauthn.get".',
        ];
    }

    #[Test]
    #[DataProvider('provideResponseWithTheTypeOfTheCeremony')]
    public function theClientDataTypeOfTheCeremonyIsAccepted(
        PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options,
        AuthenticatorAttestationResponse|AuthenticatorAssertionResponse $response
    ): void {
        $this->expectNotToPerformAssertions();

        (new CheckClientDataCollectorType())->process(self::credentialRecord(), $response, $options, null, 'example.com');
    }

    #[Test]
    #[DataProvider('provideResponseWithTheTypeOfTheOtherCeremony')]
    public function theClientDataTypeOfTheOtherCeremonyIsRejected(
        PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options,
        AuthenticatorAttestationResponse|AuthenticatorAssertionResponse $response,
        string $expectedMessage
    ): void {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage($expectedMessage);

        (new CheckClientDataCollectorType())->process(self::credentialRecord(), $response, $options, null, 'example.com');
    }

    private static function credentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            'credential-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            0,
        );
    }

    private static function creationOptions(): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Test RP'),
            PublicKeyCredentialUserEntity::create('alice', 'uid', 'Alice'),
            'challenge-bytes'
        );
    }

    private static function requestOptions(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create('challenge-bytes');
    }

    private static function attestationResponse(string $type): AuthenticatorAttestationResponse
    {
        return AuthenticatorAttestationResponse::create(
            self::clientData($type),
            AttestationObject::create(
                '',
                AttestationStatement::createNone('none', [], EmptyTrustPath::create()),
                AuthenticatorData::create('', str_repeat("\0", 32), "\0", 0)
            )
        );
    }

    private static function assertionResponse(string $type): AuthenticatorAssertionResponse
    {
        return AuthenticatorAssertionResponse::create(
            self::clientData($type),
            AuthenticatorData::create('', str_repeat("\0", 32), "\0", 0),
            'signature'
        );
    }

    private static function clientData(string $type): CollectedClientData
    {
        return CollectedClientData::create('{}', [
            'type' => $type,
            'challenge' => 'challenge-bytes',
            'origin' => 'https://example.com',
        ]);
    }
}
