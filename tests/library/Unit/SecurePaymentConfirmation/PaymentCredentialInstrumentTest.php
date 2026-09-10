<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;

/**
 * @internal
 */
final class PaymentCredentialInstrumentTest extends TestCase
{
    #[Test]
    public function paymentCredentialInstrumentCanBeCreated(): void
    {
        $instrument = PaymentCredentialInstrument::create(
            'Visa •••• 1234',
            'https://example.com/visa-icon.png'
        );

        static::assertSame('Visa •••• 1234', $instrument->displayName);
        static::assertSame('https://example.com/visa-icon.png', $instrument->icon);
        static::assertTrue($instrument->iconMustBeShown);
        static::assertNull($instrument->details);
    }

    #[Test]
    public function paymentCredentialInstrumentCanBeCreatedWithCustomIconMustBeShown(): void
    {
        $instrument = PaymentCredentialInstrument::create(
            'MasterCard •••• 5678',
            'https://example.com/mc-icon.png',
            false
        );

        static::assertFalse($instrument->iconMustBeShown);
    }

    #[Test]
    public function paymentCredentialInstrumentCanBeCreatedWithDetails(): void
    {
        $instrument = PaymentCredentialInstrument::create(
            'Visa •••• 1234',
            'https://example.com/visa-icon.png',
            details: '1234',
        );

        static::assertSame('1234', $instrument->details);
    }

    #[Test]
    public function paymentCredentialInstrumentCanBeCreatedWithConstructor(): void
    {
        $instrument = new PaymentCredentialInstrument(
            'Amex •••• 9012',
            'https://example.com/amex-icon.png'
        );

        static::assertSame('Amex •••• 9012', $instrument->displayName);
        static::assertSame('https://example.com/amex-icon.png', $instrument->icon);
        static::assertTrue($instrument->iconMustBeShown);
        static::assertNull($instrument->details);
    }

    #[Test]
    public function emptyDisplayNameIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The displayName must not be empty.');

        new PaymentCredentialInstrument('', 'https://example.com/icon.png');
    }

    #[Test]
    public function emptyIconIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The icon must not be empty.');

        new PaymentCredentialInstrument('Card', '');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidIconUrls(): iterable
    {
        yield 'plain text' => ['not-a-url'];
        yield 'missing scheme' => ['example.com/icon.png'];
        yield 'protocol-relative only' => ['//example.com/icon.png'];
        yield 'spaces in middle' => ['https:// example.com/icon.png'];
    }

    #[Test]
    #[DataProvider('provideInvalidIconUrls')]
    public function invalidIconUrlIsRejected(string $icon): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The icon must be a valid URL.');

        new PaymentCredentialInstrument('Card', $icon);
    }
}
