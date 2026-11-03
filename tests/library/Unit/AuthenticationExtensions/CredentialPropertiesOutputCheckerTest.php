<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\CredentialPropertiesInputExtension;
use Webauthn\AuthenticationExtensions\CredentialPropertiesOutputChecker;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * @internal
 */
final class CredentialPropertiesOutputCheckerTest extends TestCase
{
    #[Test]
    public function credPropsNotRequestedShouldPass(): void
    {
        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('credProps', [
                    'rk' => 'invalid-but-ignored',
                ]),
            ]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function credPropsRequestedButNotReturnedShouldPass(): void
    {
        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function credPropsOutputWithNullValueShouldPass(): void
    {
        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([AuthenticationExtension::create('credProps', null)]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function nonArrayOutputShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid credProps extension output format');

        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([AuthenticationExtension::create('credProps', 'plain-string')]),
        );
    }

    #[Test]
    public function nonBooleanRkShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"rk"');

        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('credProps', [
                    'rk' => 1,
                ]),
            ]),
        );
    }

    #[Test]
    public function nonStringAuthenticatorDisplayNameShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"authenticatorDisplayName"');

        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('credProps', [
                    'rk' => true,
                    'authenticatorDisplayName' => ['nope'],
                ]),
            ]),
        );
    }

    #[Test]
    public function fullyValidOutputShouldPass(): void
    {
        (new CredentialPropertiesOutputChecker())->check(
            new AuthenticationExtensions([CredentialPropertiesInputExtension::enable()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('credProps', [
                    'rk' => true,
                    'authenticatorDisplayName' => 'Pixel 8',
                ]),
            ]),
        );
        $this->expectNotToPerformAssertions();
    }
}
