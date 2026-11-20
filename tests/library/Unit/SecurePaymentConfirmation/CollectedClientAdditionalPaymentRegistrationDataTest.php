<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentRegistrationData;

/**
 * @internal
 */
final class CollectedClientAdditionalPaymentRegistrationDataTest extends TestCase
{
    #[Test]
    public function canBeCreatedWithABrowserBoundPublicKey(): void
    {
        $key = BrowserBoundPublicKey::create("\xa5\x01\x02");

        $registrationData = CollectedClientAdditionalPaymentRegistrationData::create($key);

        static::assertSame($key, $registrationData->browserBoundPublicKey);
    }

    #[Test]
    public function theBrowserBoundPublicKeyIsOptional(): void
    {
        static::assertNull(CollectedClientAdditionalPaymentRegistrationData::create()->browserBoundPublicKey);
        static::assertNull((new CollectedClientAdditionalPaymentRegistrationData())->browserBoundPublicKey);
    }
}
