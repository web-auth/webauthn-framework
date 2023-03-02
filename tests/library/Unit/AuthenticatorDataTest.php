<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestedCredentialData;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticatorData;

/**
 * @internal
 */
final class AuthenticatorDataTest extends TestCase
{
    #[Test]
    public function anAuthenticatorDataCanBeCreatedAndValueAccessed(): void
    {
        $attestedCredentialData = new AttestedCredentialData(Uuid::v4(), '', null);
        $extensions = new AuthenticationExtensionsClientOutputs();

        $authenticatorData = new AuthenticatorData(
            'auth_data',
            'rp_id_hash',
            'A',
            100,
            $attestedCredentialData,
            $extensions
        );

        static::assertSame('auth_data', $authenticatorData->getAuthData());
        static::assertSame('rp_id_hash', $authenticatorData->getRpIdHash());
        static::assertTrue($authenticatorData->isUserPresent());
        static::assertFalse($authenticatorData->isUserVerified());
        static::assertSame(100, $authenticatorData->getSignCount());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse1());
        static::assertSame(0, $authenticatorData->getReservedForFutureUse2());
        static::assertTrue($authenticatorData->hasAttestedCredentialData());
        static::assertInstanceOf(AttestedCredentialData::class, $authenticatorData->getAttestedCredentialData());
        static::assertFalse($authenticatorData->hasExtensions());
        static::assertNull($authenticatorData->getExtensions());
    }
}
