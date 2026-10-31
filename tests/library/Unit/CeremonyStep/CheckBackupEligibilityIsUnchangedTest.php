<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\CeremonyStep;

use function chr;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CheckBackupEligibilityIsUnchanged;
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
 * Issue #969: the BE flag of an assertion is compared with the value recorded for the credential, which MUST NOT
 * change during the life of the credential.
 *
 * @internal
 */
final class CheckBackupEligibilityIsUnchangedTest extends AbstractTestCase
{
    /**
     * @return iterable<string, array{bool, int}>
     */
    public static function unchangedBackupEligibility(): iterable
    {
        yield 'multi-device credential, backed up' => [
            true,
            AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE | AuthenticatorData::FLAG_BS,
        ];
        yield 'multi-device credential, not backed up' => [true, AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE];
        yield 'single-device credential' => [false, AuthenticatorData::FLAG_UP];
    }

    /**
     * @return iterable<string, array{bool, int}>
     */
    public static function changedBackupEligibility(): iterable
    {
        yield 'multi-device credential claimed as single-device' => [true, AuthenticatorData::FLAG_UP];
        yield 'single-device credential claimed as multi-device' => [
            false,
            AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE,
        ];
        yield 'single-device credential claimed as backed up' => [
            false,
            AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE | AuthenticatorData::FLAG_BS,
        ];
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function anyBackupEligibility(): iterable
    {
        yield 'BE flag set' => [AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE];
        yield 'BE flag clear' => [AuthenticatorData::FLAG_UP];
    }

    #[Test]
    #[DataProvider('unchangedBackupEligibility')]
    public function anAssertionThatKeepsTheRecordedBackupEligibilityIsAccepted(bool $recorded, int $flags): void
    {
        $credentialRecord = $this->credentialRecord($recorded);

        (new CheckBackupEligibilityIsUnchanged())->process(
            $credentialRecord,
            $this->assertionResponse($flags),
            PublicKeyCredentialRequestOptions::create('challenge-bytes'),
            null,
            'example.com'
        );

        static::assertSame($recorded, $credentialRecord->backupEligible);
    }

    #[Test]
    #[DataProvider('changedBackupEligibility')]
    public function anAssertionThatChangesTheRecordedBackupEligibilityIsRejected(bool $recorded, int $flags): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The backup eligibility flag does not match the value recorded for the credential.'
        );

        (new CheckBackupEligibilityIsUnchanged())->process(
            $this->credentialRecord($recorded),
            $this->assertionResponse($flags),
            PublicKeyCredentialRequestOptions::create('challenge-bytes'),
            null,
            'example.com'
        );
    }

    #[Test]
    #[DataProvider('anyBackupEligibility')]
    public function aCredentialRecordWithoutRecordedBackupEligibilityIsNotChecked(int $flags): void
    {
        $credentialRecord = $this->credentialRecord(null);

        (new CheckBackupEligibilityIsUnchanged())->process(
            $credentialRecord,
            $this->assertionResponse($flags),
            PublicKeyCredentialRequestOptions::create('challenge-bytes'),
            null,
            'example.com'
        );

        static::assertNull($credentialRecord->backupEligible);
    }

    #[Test]
    public function theRegistrationCeremonyIsNotChecked(): void
    {
        $credentialRecord = $this->credentialRecord(true);

        (new CheckBackupEligibilityIsUnchanged())->process(
            $credentialRecord,
            $this->attestationResponse(AuthenticatorData::FLAG_UP),
            PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create('Test RP'),
                PublicKeyCredentialUserEntity::create('alice', 'uid', 'Alice'),
                'challenge-bytes'
            ),
            null,
            'example.com'
        );

        static::assertTrue($credentialRecord->backupEligible);
    }

    private function credentialRecord(?bool $backupEligible): CredentialRecord
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
            null,
            $backupEligible
        );
    }

    private function assertionResponse(int $flags): AuthenticatorAssertionResponse
    {
        return AuthenticatorAssertionResponse::create(
            CollectedClientData::create('{}', [
                'type' => 'webauthn.get',
                'challenge' => 'challenge-bytes',
                'origin' => 'https://example.com',
            ]),
            AuthenticatorData::create('', str_repeat("\0", 32), chr($flags), 0),
            'signature'
        );
    }

    private function attestationResponse(int $flags): AuthenticatorAttestationResponse
    {
        return AuthenticatorAttestationResponse::create(
            CollectedClientData::create('{}', [
                'type' => 'webauthn.create',
                'challenge' => 'challenge-bytes',
                'origin' => 'https://example.com',
            ]),
            AttestationObject::create(
                '',
                AttestationStatement::createNone('none', [], EmptyTrustPath::create()),
                AuthenticatorData::create('', str_repeat("\0", 32), chr($flags), 0)
            )
        );
    }
}
