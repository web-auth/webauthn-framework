<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

/**
 * @internal
 */
final class CollectedClientAdditionalPaymentDataTest extends TestCase
{
    #[Test]
    public function canBeCreatedWithFactoryMethod(): void
    {
        $total = PaymentCurrencyAmount::create('USD', '99.99');
        $instrument = PaymentCredentialInstrument::create(
            'Visa •••• 1234',
            'https://example.com/visa-icon.png'
        );

        $paymentData = CollectedClientAdditionalPaymentData::create(
            rpId: 'example.com',
            topOrigin: 'https://merchant.example.com',
            total: $total,
            instrument: $instrument,
            payeeName: 'Merchant Store',
            payeeOrigin: 'https://merchant.example.com',
        );

        static::assertSame('example.com', $paymentData->rpId);
        static::assertSame('https://merchant.example.com', $paymentData->topOrigin);
        static::assertSame('Merchant Store', $paymentData->payeeName);
        static::assertSame('https://merchant.example.com', $paymentData->payeeOrigin);
        static::assertSame($total, $paymentData->total);
        static::assertSame($instrument, $paymentData->instrument);
    }

    #[Test]
    public function canBeCreatedWithConstructor(): void
    {
        $total = new PaymentCurrencyAmount('EUR', '50.00');
        $instrument = new PaymentCredentialInstrument(
            'MasterCard •••• 5678',
            'https://example.com/mc-icon.png'
        );

        $paymentData = new CollectedClientAdditionalPaymentData(
            rpId: 'store.com',
            topOrigin: 'https://top.example.com',
            total: $total,
            instrument: $instrument,
        );

        static::assertSame($total, $paymentData->total);
        static::assertSame($instrument, $paymentData->instrument);
    }

    #[Test]
    public function emptyRpIdIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The rpId must not be empty.');

        new CollectedClientAdditionalPaymentData(
            rpId: '',
            topOrigin: 'https://top.example.com',
            total: new PaymentCurrencyAmount('USD', '10.00'),
            instrument: new PaymentCredentialInstrument('Card', 'https://example.com/icon.png'),
        );
    }

    #[Test]
    public function emptyTopOriginIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The topOrigin must not be empty.');

        new CollectedClientAdditionalPaymentData(
            rpId: 'example.com',
            topOrigin: '',
            total: new PaymentCurrencyAmount('USD', '10.00'),
            instrument: new PaymentCredentialInstrument('Card', 'https://example.com/icon.png'),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidUrls(): iterable
    {
        yield 'plain text' => ['merchant.example.com'];
        yield 'with spaces' => ['https:// merchant.example.com'];
        yield 'just scheme' => ['https://'];
    }

    #[Test]
    #[DataProvider('provideInvalidUrls')]
    public function invalidTopOriginUrlIsRejected(string $topOrigin): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The topOrigin must be a valid URL.');

        new CollectedClientAdditionalPaymentData(
            rpId: 'example.com',
            topOrigin: $topOrigin,
            total: new PaymentCurrencyAmount('USD', '10.00'),
            instrument: new PaymentCredentialInstrument('Card', 'https://example.com/icon.png'),
        );
    }

    #[Test]
    #[DataProvider('provideInvalidUrls')]
    public function invalidPayeeOriginUrlIsRejected(string $payeeOrigin): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The payeeOrigin must be a valid URL.');

        new CollectedClientAdditionalPaymentData(
            rpId: 'example.com',
            topOrigin: 'https://top.example.com',
            total: new PaymentCurrencyAmount('USD', '10.00'),
            instrument: new PaymentCredentialInstrument('Card', 'https://example.com/icon.png'),
            payeeOrigin: $payeeOrigin,
        );
    }

    #[Test]
    public function emptyPayeeOriginIsAllowed(): void
    {
        $paymentData = new CollectedClientAdditionalPaymentData(
            rpId: 'example.com',
            topOrigin: 'https://top.example.com',
            total: new PaymentCurrencyAmount('USD', '10.00'),
            instrument: new PaymentCredentialInstrument('Card', 'https://example.com/icon.png'),
        );

        static::assertSame('', $paymentData->payeeName);
        static::assertSame('', $paymentData->payeeOrigin);
    }
}
