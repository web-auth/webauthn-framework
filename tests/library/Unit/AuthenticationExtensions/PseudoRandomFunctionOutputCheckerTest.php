<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtensionBuilder;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionOutputChecker;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * @internal
 */
final class PseudoRandomFunctionOutputCheckerTest extends TestCase
{
    #[Test]
    public function absentAuthenticatorOutputShouldPass(): void
    {
        (new PseudoRandomFunctionOutputChecker())->check(
            new AuthenticationExtensions([
                PseudoRandomFunctionInputExtensionBuilder::create()
                    ->withInputs('salt-bytes')
                    ->build(),
            ]),
            new AuthenticationExtensions([]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function unrelatedAuthenticatorOutputsShouldPass(): void
    {
        (new PseudoRandomFunctionOutputChecker())->check(
            new AuthenticationExtensions([
                PseudoRandomFunctionInputExtensionBuilder::create()
                    ->withInputs('salt-bytes')
                    ->build(),
            ]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('hmac-secret', true),
                AuthenticationExtension::create('credProtect', 2),
            ]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function prfAuthenticatorOutputShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('The authenticator extension outputs must not contain a "prf" entry');

        (new PseudoRandomFunctionOutputChecker())->check(
            new AuthenticationExtensions([
                PseudoRandomFunctionInputExtensionBuilder::create()
                    ->withInputs('salt-bytes')
                    ->build(),
            ]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('prf', [
                    'results' => [
                        'first' => 'cleartext-prf-output',
                    ],
                ]),
            ]),
        );
    }

    #[Test]
    public function prfAuthenticatorOutputShouldFailEvenWhenNotRequested(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('PRF results are client-side only');

        (new PseudoRandomFunctionOutputChecker())->check(
            new AuthenticationExtensions([]),
            new AuthenticationExtensions([AuthenticationExtension::create('prf', true)]),
        );
    }
}
