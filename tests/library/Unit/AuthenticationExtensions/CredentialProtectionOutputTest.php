<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\CredentialProtectionOutput;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @internal
 */
final class CredentialProtectionOutputTest extends TestCase
{
    #[Test]
    public function fromExtensionsReturnsNullWhenAbsent(): void
    {
        static::assertNull(CredentialProtectionOutput::fromExtensions(new AuthenticationExtensions([])));
    }

    #[Test]
    public function fromExtensionsParsesSupportedPolicies(): void
    {
        foreach (CredentialProtectionOutput::POLICIES as $policy) {
            $output = CredentialProtectionOutput::fromExtensions(new AuthenticationExtensions([
                AuthenticationExtension::create('credProtect', $policy),
            ]));

            static::assertNotNull($output);
            static::assertSame($policy, $output->policy);
        }
    }

    #[Test]
    public function fromExtensionRejectsNonCredProtectExtension(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('not a "credProtect"');

        CredentialProtectionOutput::fromExtension(AuthenticationExtension::create('appid', 1));
    }

    #[Test]
    public function fromExtensionRejectsNonIntegerValue(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must be an integer');

        CredentialProtectionOutput::fromExtension(AuthenticationExtension::create('credProtect', '1'));
    }

    #[Test]
    public function fromExtensionRejectsOutOfRangeValue(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('1, 2 or 3');

        CredentialProtectionOutput::fromExtension(AuthenticationExtension::create('credProtect', 4));
    }

    #[Test]
    public function constructorRejectsZero(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('1, 2 or 3');

        new CredentialProtectionOutput(0);
    }
}
