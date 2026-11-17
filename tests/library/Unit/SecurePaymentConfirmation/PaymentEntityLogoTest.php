<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\PaymentEntityLogo;

/**
 * @internal
 */
final class PaymentEntityLogoTest extends TestCase
{
    #[Test]
    public function canBeCreated(): void
    {
        $logo = PaymentEntityLogo::create('https://example.com/visa.svg', 'Visa');

        static::assertSame('https://example.com/visa.svg', $logo->url);
        static::assertSame('Visa', $logo->label);
    }

    #[Test]
    public function emptyUrlIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The url must not be empty.');

        new PaymentEntityLogo('', 'Visa');
    }

    #[Test]
    public function emptyLabelIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The label must not be empty.');

        new PaymentEntityLogo('https://example.com/visa.svg', '');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidUrls(): iterable
    {
        yield 'plain text' => ['not-a-url'];
        yield 'missing scheme' => ['example.com/logo.png'];
        yield 'with spaces' => ['https:// example.com/logo.png'];
    }

    #[Test]
    #[DataProvider('provideInvalidUrls')]
    public function invalidUrlIsRejected(string $url): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The url must be a valid URL.');

        new PaymentEntityLogo($url, 'Visa');
    }
}
