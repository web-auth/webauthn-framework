<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\FakeCredentialShape;

/**
 * @internal
 */
final class FakeCredentialShapeTest extends TestCase
{
    #[Test]
    public function theTransportsAreKeptUniqueAndInLexicographicOrder(): void
    {
        $shape = FakeCredentialShape::create(64, ['usb', 'nfc', 'usb']);

        static::assertSame(64, $shape->credentialIdLength);
        static::assertSame(['nfc', 'usb'], $shape->transports);
    }

    #[Test]
    public function aShapeCanHaveNoTransports(): void
    {
        static::assertSame([], FakeCredentialShape::create(64)->transports);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function acceptedLengths(): iterable
    {
        yield 'shortest' => [16];
        yield 'longest' => [1023];
    }

    #[Test]
    #[DataProvider('acceptedLengths')]
    public function theCredentialIdLengthGoesFrom16To1023Bytes(int $length): void
    {
        static::assertSame($length, FakeCredentialShape::create($length)->credentialIdLength);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function rejectedLengths(): iterable
    {
        yield 'too short' => [15];
        yield 'too long' => [1024];
    }

    #[Test]
    #[DataProvider('rejectedLengths')]
    public function aCredentialIdLengthOutsideThatRangeIsRejected(int $length): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The credential ID length must be between 16 and 1023 bytes');

        FakeCredentialShape::create($length);
    }
}
