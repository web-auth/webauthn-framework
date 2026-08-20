<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use function chr;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CheckUserVerification;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Verify the `$requireUserVerification` opt-out and the runtime mediation override on
 * `PublicKeyCredentialCreationOptions::$mediation` are honored by CheckUserVerification.
 *
 * @internal
 */
final class CheckUserVerificationTest extends AbstractTestCase
{
    #[Test]
    public function strictStepThrowsWhenUserWasNotVerifiedAndOptionsHaveNoMediation(): void
    {
        $step = new CheckUserVerification(requireUserVerification: true);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('User authentication required.');

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUvFlag(false),
            $this->creationOptions(mediation: null),
            null,
            'example.com',
        );
    }

    #[Test]
    public function strictStepIsBypassedWhenOptionsRequestConditionalMediation(): void
    {
        $step = new CheckUserVerification(requireUserVerification: true);

        // Must NOT throw — `mediation: conditional` opts out of the User Verification requirement at runtime.
        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUvFlag(false),
            $this->creationOptions(mediation: PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function lenientStepIsBypassedRegardlessOfMediation(): void
    {
        // CeremonyStepManagerFactory::conditionalCreateCeremony() builds the step with requireUserVerification=false.
        // That static fallback must keep working when no mediation hint is set on the options.
        $step = new CheckUserVerification(requireUserVerification: false);

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUvFlag(false),
            $this->creationOptions(mediation: null),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function strictStepAllowsValidUserVerificationRegardlessOfMediation(): void
    {
        $step = new CheckUserVerification(requireUserVerification: true);

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUvFlag(true),
            $this->creationOptions(mediation: null),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
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

    private function creationOptions(?string $mediation): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Test RP'),
            PublicKeyCredentialUserEntity::create('alice', 'uid', 'Alice'),
            'challenge-bytes',
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ),
            mediation: $mediation,
        );
    }

    private function attestationResponseWithUvFlag(bool $userVerified): AuthenticatorAttestationResponse
    {
        $flags = chr(AuthenticatorData::FLAG_UP | ($userVerified ? AuthenticatorData::FLAG_UV : 0));
        $authData = AuthenticatorData::create(
            authData: '',
            rpIdHash: str_repeat("\0", 32),
            flags: $flags,
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
                attStmt: AttestationStatement::createNone('none', [], EmptyTrustPath::create()),
                authData: $authData,
            ),
        );
    }
}
