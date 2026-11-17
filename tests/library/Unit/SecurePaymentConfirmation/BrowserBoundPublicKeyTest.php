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
        $key = BrowserBoundPublicKey::create("\x01\x02\x03", -7);

        static::assertSame("\x01\x02\x03", $key->publicKey);
        static::assertSame(-7, $key->algorithm);
    }

    #[Test]
    public function emptyPublicKeyIsRejected(): void
    {
        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('The publicKey must not be empty.');

        new BrowserBoundPublicKey('', -7);
    }
}
