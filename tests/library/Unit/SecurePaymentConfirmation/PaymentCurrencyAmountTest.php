<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

/**
 * @internal
 */
final class PaymentCurrencyAmountTest extends TestCase
{
    #[Test]
    public function paymentCurrencyAmountCanBeCreated(): void
    {
        $amount = PaymentCurrencyAmount::create('USD', '10.00');

        static::assertSame('USD', $amount->currency);
        static::assertSame('10.00', $amount->value);
    }

    #[Test]
    public function paymentCurrencyAmountCanBeCreatedWithConstructor(): void
    {
        $amount = new PaymentCurrencyAmount('EUR', '25.50');

        static::assertSame('EUR', $amount->currency);
        static::assertSame('25.50', $amount->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidValues(): iterable
    {
        yield 'integer' => ['100'];
        yield 'decimal' => ['9.99'];
        yield 'zero' => ['0'];
        yield 'sub-cent' => ['0.0001'];
        yield 'negative refund' => ['-50.00'];
    }

    #[Test]
    #[DataProvider('provideValidValues')]
    public function validValueFormatsAreAccepted(string $value): void
    {
        $amount = new PaymentCurrencyAmount('USD', $value);

        static::assertSame($value, $amount->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidCurrencies(): iterable
    {
        yield 'empty' => [''];
        yield 'lowercase' => ['usd'];
        yield 'two letters' => ['US'];
        yield 'four letters' => ['USDA'];
        yield 'numeric ISO' => ['840'];
        yield 'mixed case' => ['Usd'];
        yield 'with whitespace' => ['USD '];
    }

    #[Test]
    #[DataProvider('provideInvalidCurrencies')]
    public function invalidCurrencyIsRejected(string $currency): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('ISO 4217');

        new PaymentCurrencyAmount($currency, '10.00');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidValues(): iterable
    {
        yield 'empty' => [''];
        yield 'plus sign' => ['+10'];
        yield 'comma decimal' => ['10,00'];
        yield 'trailing dot' => ['10.'];
        yield 'leading dot' => ['.50'];
        yield 'letters' => ['1e2'];
        yield 'currency symbol' => ['$10'];
        yield 'thousands separator' => ['1,000.00'];
    }

    #[Test]
    #[DataProvider('provideInvalidValues')]
    public function invalidValueIsRejected(string $value): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('decimal monetary amount');

        new PaymentCurrencyAmount('USD', $value);
    }
}
