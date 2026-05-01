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
use Webauthn\CeremonyStep\CheckUserWasPresent;
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
 * Issue #831 — verify the runtime mediation override on `PublicKeyCredentialCreationOptions::$mediation`
 * is honored by CheckUserWasPresent, regardless of the constructor flag.
 *
 * @internal
 */
final class CheckUserWasPresentTest extends AbstractTestCase
{
    #[Test]
    public function strictStepThrowsWhenUserWasNotPresentAndOptionsHaveNoMediation(): void
    {
        $step = new CheckUserWasPresent(requireUserPresence: true);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('User was not present');

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUpFlag(false),
            $this->creationOptions(mediation: null),
            null,
            'example.com',
        );
    }

    #[Test]
    public function strictStepIsBypassedWhenOptionsRequestConditionalMediation(): void
    {
        $step = new CheckUserWasPresent(requireUserPresence: true);

        // Must NOT throw — `mediation: conditional` opts out of the User Presence requirement at runtime.
        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUpFlag(false),
            $this->creationOptions(mediation: PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function strictStepStillRunsWhenOptionsExplicitlyRequestDefaultMediation(): void
    {
        $step = new CheckUserWasPresent(requireUserPresence: true);

        $this->expectException(AuthenticatorResponseVerificationException::class);

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUpFlag(false),
            $this->creationOptions(mediation: PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT),
            null,
            'example.com',
        );
    }

    #[Test]
    public function lenientStepKeepsWorkingForBackwardCompatibility(): void
    {
        // CeremonyStepManagerFactory::conditionalCreateCeremony() builds the step with requireUserPresence=false.
        // That static fallback must keep working when no mediation hint is set on the options.
        $step = new CheckUserWasPresent(requireUserPresence: false);

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUpFlag(false),
            $this->creationOptions(mediation: null),
            null,
            'example.com',
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function strictStepAllowsValidUserPresenceRegardlessOfMediation(): void
    {
        $step = new CheckUserWasPresent(requireUserPresence: true);

        $step->process(
            $this->credentialRecord(),
            $this->attestationResponseWithUpFlag(true),
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
            mediation: $mediation,
        );
    }

    private function attestationResponseWithUpFlag(bool $userPresent): AuthenticatorAttestationResponse
    {
        $flags = chr($userPresent ? AuthenticatorData::FLAG_UP : 0);
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
