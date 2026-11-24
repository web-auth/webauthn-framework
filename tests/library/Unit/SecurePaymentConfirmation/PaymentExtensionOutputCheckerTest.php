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
 * The checker receives the AUTHENTICATOR extension outputs. The `payment` extension has none: its output is a client
 * extension result, verified by CheckBrowserBoundSignature.
 *
 * @internal
 */
final class PaymentExtensionOutputCheckerTest extends TestCase
{
    #[Test]
    public function authenticatorOutputsWithoutPaymentEntryArePassedEvenWhenThePaymentWasRequested(): void
    {
        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([AuthenticationExtension::create('credProtect', 2)]),
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function emptyAuthenticatorOutputsArePassed(): void
    {
        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions(),
        );

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function aPaymentEntryInTheAuthenticatorOutputsIsRejected(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('must not contain a "payment" entry');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions([PaymentExtension::register()]),
            new AuthenticationExtensions([
                AuthenticationExtension::create('payment', [
                    'browserBoundSignature' => [
                        'signature' => 'c2lnbmF0dXJl',
                    ],
                ]),
            ]),
        );
    }

    #[Test]
    public function aPaymentEntryInTheAuthenticatorOutputsIsRejectedWhenThePaymentWasNotRequested(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('must not contain a "payment" entry');

        (new PaymentExtensionOutputChecker())->check(
            new AuthenticationExtensions(),
            new AuthenticationExtensions([AuthenticationExtension::create('payment', [])]),
        );
    }
}
