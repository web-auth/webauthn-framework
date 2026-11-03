<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\CredentialProtectionInputExtension;

/**
 * @internal
 */
final class CredentialProtectionInputExtensionTest extends TestCase
{
    #[Test]
    public function userVerificationOptionalProducesPolicyString(): void
    {
        $extension = CredentialProtectionInputExtension::userVerificationOptional();

        static::assertSame('credentialProtectionPolicy', $extension->name);
        static::assertSame('userVerificationOptional', $extension->value);
    }

    #[Test]
    public function userVerificationOptionalWithCredentialIDListProducesPolicyString(): void
    {
        $extension = CredentialProtectionInputExtension::userVerificationOptionalWithCredentialIDList();

        static::assertSame('credentialProtectionPolicy', $extension->name);
        static::assertSame('userVerificationOptionalWithCredentialIDList', $extension->value);
    }

    #[Test]
    public function userVerificationRequiredProducesPolicyString(): void
    {
        $extension = CredentialProtectionInputExtension::userVerificationRequired();

        static::assertSame('credentialProtectionPolicy', $extension->name);
        static::assertSame('userVerificationRequired', $extension->value);
    }

    #[Test]
    public function enforceCompanionExtensionIsBoolean(): void
    {
        $extension = CredentialProtectionInputExtension::enforce();

        static::assertSame('enforceCredentialProtectionPolicy', $extension->name);
        static::assertTrue($extension->value);
    }
}
