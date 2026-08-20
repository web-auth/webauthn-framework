<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use function chr;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorData;

/**
 * @internal
 */
final class AuthenticatorDataTest extends TestCase
{
    #[Test]
    public function authenticatorDataCanBeCreatedAndValuesAccessed(): void
    {
        // Given
        $attestedCredentialData = AttestedCredentialData::create(Uuid::v4(), '');
        $extensions = AuthenticationExtensions::create();

        // When
        $authenticatorData = AuthenticatorData::create(
            'auth_data',
            'rp_id_hash',
            'A',
            100,
            $attestedCredentialData,
            $extensions
        );

        // Then
        static::assertSame('auth_data', $authenticatorData->authData);
        static::assertSame('rp_id_hash', $authenticatorData->rpIdHash);
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertSame(100, $authenticatorData->signCount);
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->attestedCredentialData);
        static::assertFalse($authenticatorData->hasExtensions());
        static::assertSame(0, $authenticatorData->extensions->count());
    }

    /**
     * Bits 3 and 4 were reserved in Webauthn Level 2 and have been assigned to BE and BS in Level 3, so only bit 5 is
     * still reported as reserved.
     */
    #[Test]
    public function theBackupFlagsAreNotReportedAsReservedForFutureUse(): void
    {
        // Given
        $flags = chr(
            AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_UV | AuthenticatorData::FLAG_BE | AuthenticatorData::FLAG_BS
        );

        // When
        $authenticatorData = AuthenticatorData::create('auth_data', 'rp_id_hash', $flags, 0);

        // Then
        static::assertTrue($authenticatorData->isBackupEligible());
        static::assertTrue($authenticatorData->isBackedUp());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
    }

    #[Test]
    public function theRemainingReservedBitIsStillReported(): void
    {
        // Given
        $flags = chr(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_RFU1 | AuthenticatorData::FLAG_RFU2);

        // When
        $authenticatorData = AuthenticatorData::create('auth_data', 'rp_id_hash', $flags, 0);

        // Then
        static::assertSame(AuthenticatorData::FLAG_RFU1, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(AuthenticatorData::FLAG_RFU2, $authenticatorData->getReservedForFutureUse2());
    }
}
