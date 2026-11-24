<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\SecurePaymentConfirmation;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\Exception\InvalidDataException;
use Webauthn\SecurePaymentConfirmation\BrowserBoundPublicKey;

/**
 * @internal
 */
final class BrowserBoundPublicKeyTest extends TestCase
{
    #[Test]
    public function canBeCreated(): void
    {
        $key = BrowserBoundPublicKey::create("\xa5\x01\x02");

        static::assertSame("\xa5\x01\x02", $key->publicKey);
    }

    #[Test]
    public function emptyPublicKeyIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The browser-bound public key must not be empty.');

        new BrowserBoundPublicKey('');
    }
}
