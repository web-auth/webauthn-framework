<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\Exception\AuthenticatorResponseVerificationException;

/**
 * @internal
 */
final class PaymentExtensionOutputCheckerTest extends TestCase
{
    #[Test]
    public function paymentExtensionNotRequestedShouldPass(): void
    {
        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([]),
            new AuthenticationExtensions([]),
        );
        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function paymentExtensionRequestedButNotReturnedShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('not returned in the response');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([]),
        );
    }

    #[Test]
    public function nonArrayOutputShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid payment extension output format');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([AuthenticationExtension::create('payment', 'plain-string')]),
        );
    }

    #[Test]
    public function missingBrowserBoundSignatureShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"browserBoundSignature"');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('payment', [
                    'somethingElse' => true,
                ]),
            ]),
        );
    }

    #[Test]
    public function emptySignatureShouldFail(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('missing or empty');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('payment', [
                    'browserBoundSignature' => [
                        'signature' => '',
                    ],
                ]),
            ]),
        );
    }

    #[Test]
    public function validBrowserBoundSignatureShouldPass(): void
    {
        // base64url("hello") = aGVsbG8
        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('payment', [
                    'browserBoundSignature' => [
                        'signature' => 'aGVsbG8',
                    ],
                ]),
            ]),
        );
        $this->expectNotToPerformAssertions();
    }
}
