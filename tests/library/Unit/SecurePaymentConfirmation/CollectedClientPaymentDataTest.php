<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

/**
 * @internal
 */
final class CollectedClientPaymentDataTest extends TestCase
{
    #[Test]
    public function canBeCreated(): void
    {
        $additionalData = $this->createAdditionalData();

        $paymentData = CollectedClientPaymentData::create($additionalData);

        static::assertSame($additionalData, $paymentData->payment);
        static::assertSame('example.com', $paymentData->payment->rpId);
    }

    #[Test]
    public function canBeCreatedWithConstructor(): void
    {
        $additionalData = $this->createAdditionalData();

        $paymentData = new CollectedClientPaymentData($additionalData);

        static::assertSame($additionalData, $paymentData->payment);
    }

    private function createAdditionalData(): CollectedClientAdditionalPaymentData
    {
        return CollectedClientAdditionalPaymentData::create(
            rpId: 'example.com',
            topOrigin: 'https://top.example.com',
            total: PaymentCurrencyAmount::create('USD', '150.00'),
            instrument: PaymentCredentialInstrument::create(
                'Visa •••• 1234',
                'https://example.com/visa-icon.png'
            ),
            payeeName: 'Merchant Store',
            payeeOrigin: 'https://merchant.example.com',
        );
    }
}
