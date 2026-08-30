<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundSignature;

/**
 * @internal
 */
final class BrowserBoundSignatureTest extends TestCase
{
    #[Test]
    public function canBeCreated(): void
    {
        $signature = BrowserBoundSignature::create("\x01\x02\x03");

        static::assertSame("\x01\x02\x03", $signature->signature);
    }

    #[Test]
    public function emptySignatureIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The signature must not be empty.');

        new BrowserBoundSignature('');
    }
}
