<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckAttestationFormatIsKnownAndValid;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class CheckAttestationFormatIsKnownAndValidTest extends TestCase
{
    #[Test]
    public function emptyAttestationFormatsListAcceptsAnySupportedFormat(): void
    {
        $step = new CheckAttestationFormatIsKnownAndValid($this->supportManagerAccepting('packed', valid: true));

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithFormat('packed'),
            $this->creationOptions([]),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function nonEmptyAttestationFormatsListAcceptsMatchingFormat(): void
    {
        $step = new CheckAttestationFormatIsKnownAndValid($this->supportManagerAccepting('packed', valid: true));

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithFormat('packed'),
            $this->creationOptions(['packed', 'tpm']),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function nonEmptyAttestationFormatsListRejectsUnrequestedFormat(): void
    {
        $step = new CheckAttestationFormatIsKnownAndValid($this->supportManagerAccepting('packed', valid: true));

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"packed" is not in the list requested');

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithFormat('packed'),
            $this->creationOptions(['tpm', 'fido-u2f']),
            null,
            'example.com',
        );
    }

    private function credentialRecord(): CredentialRecord
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

    /**
     * @param string[] $attestationFormats
     */
    private function creationOptions(array $attestationFormats): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Test RP'),
            PublicKeyCredentialUserEntity::create('alice', 'uid', 'Alice'),
            'challenge-bytes',
            attestationFormats: $attestationFormats,
        );
    }

    private function attestationResponseWithFormat(string $fmt): AuthenticatorAttestationResponse
    {
        $authData = AuthenticatorData::create(
            authData: '',
            rpIdHash: str_repeat("\0", 32),
            flags: "\x01",
            signCount: 0,
        );

        return AuthenticatorAttestationResponse::create(
            CollectedClientData::create('{}', [
                'type' => 'webauthn.create',
                'challenge' => 'challenge-bytes',
                'origin' => 'https://example.com',
            ]),
            AttestationObject::create(
                rawAttestationObject: '',
                attStmt: AttestationStatement::createNone($fmt, [], EmptyTrustPath::create()),
                authData: $authData,
            ),
        );
    }

    private function supportManagerAccepting(string $fmt, bool $valid): AttestationStatementSupportManager
    {
        /** @var AttestationStatementSupport&MockObject $support */
        $support = $this->createMock(AttestationStatementSupport::class);
        $support->method('name')
            ->willReturn($fmt);
        $support->method('isValid')
            ->willReturn($valid);

        $manager = AttestationStatementSupportManager::create();
        $manager->add($support);

        return $manager;
    }
}
