<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\CredentialPropertiesOutput;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @internal
 */
final class CredentialPropertiesOutputTest extends TestCase
{
    #[Test]
    public function fromExtensionsReturnsNullWhenCredPropsAbsent(): void
    {
        $extensions = new AuthenticationExtensions([]);

        static::assertNull(CredentialPropertiesOutput::fromExtensions($extensions));
    }

    #[Test]
    public function fromExtensionsParsesRkOnly(): void
    {
        $extensions = new AuthenticationExtensions([
            AuthenticationExtension::create('credProps', [
                'rk' => true,
            ]),
        ]);

        $output = CredentialPropertiesOutput::fromExtensions($extensions);

        static::assertNotNull($output);
        static::assertTrue($output->rk);
        static::assertNull($output->authenticatorDisplayName);
    }

    #[Test]
    public function fromExtensionsParsesAuthenticatorDisplayName(): void
    {
        $extensions = new AuthenticationExtensions([
            AuthenticationExtension::create('credProps', [
                'rk' => true,
                'authenticatorDisplayName' => 'My Phone',
            ]),
        ]);

        $output = CredentialPropertiesOutput::fromExtensions($extensions);

        static::assertNotNull($output);
        static::assertTrue($output->rk);
        static::assertSame('My Phone', $output->authenticatorDisplayName);
    }

    #[Test]
    public function fromExtensionAcceptsAuthenticatorDisplayNameWithoutRk(): void
    {
        $output = CredentialPropertiesOutput::fromExtension(
            AuthenticationExtension::create('credProps', [
                'authenticatorDisplayName' => 'iCloud Keychain',
            ]),
        );

        static::assertNull($output->rk);
        static::assertSame('iCloud Keychain', $output->authenticatorDisplayName);
    }

    #[Test]
    public function fromExtensionWithNullValueReturnsEmptyOutput(): void
    {
        $output = CredentialPropertiesOutput::fromExtension(AuthenticationExtension::create('credProps', null));

        static::assertNull($output->rk);
        static::assertNull($output->authenticatorDisplayName);
    }

    #[Test]
    public function fromExtensionRejectsNonCredPropsExtension(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('not a "credProps"');

        CredentialPropertiesOutput::fromExtension(AuthenticationExtension::create('appid', true));
    }

    #[Test]
    public function fromExtensionRejectsScalarValue(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('object/array');

        CredentialPropertiesOutput::fromExtension(AuthenticationExtension::create('credProps', 'oops'));
    }

    #[Test]
    public function fromExtensionRejectsNonBooleanRk(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('"credProps.rk"');

        CredentialPropertiesOutput::fromExtension(
            AuthenticationExtension::create('credProps', [
                'rk' => 'yes',
            ]),
        );
    }

    #[Test]
    public function fromExtensionRejectsNonStringAuthenticatorDisplayName(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('"credProps.authenticatorDisplayName"');

        CredentialPropertiesOutput::fromExtension(
            AuthenticationExtension::create('credProps', [
                'rk' => true,
                'authenticatorDisplayName' => 12345,
            ]),
        );
    }
}
