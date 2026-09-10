<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\MinPinLengthOutput;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @internal
 */
final class MinPinLengthOutputTest extends TestCase
{
    #[Test]
    public function fromExtensionsReturnsNullWhenAbsent(): void
    {
        $extensions = new AuthenticationExtensions([]);

        static::assertNull(MinPinLengthOutput::fromExtensions($extensions));
    }

    #[Test]
    public function fromExtensionsParsesIntegerValue(): void
    {
        $extensions = new AuthenticationExtensions([AuthenticationExtension::create('minPinLength', 6)]);

        $output = MinPinLengthOutput::fromExtensions($extensions);

        static::assertNotNull($output);
        static::assertSame(6, $output->minPinLength);
    }

    #[Test]
    public function fromExtensionAcceptsZero(): void
    {
        $output = MinPinLengthOutput::fromExtension(AuthenticationExtension::create('minPinLength', 0));

        static::assertSame(0, $output->minPinLength);
    }

    #[Test]
    public function fromExtensionRejectsNonMinPinLengthExtension(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('not a "minPinLength"');

        MinPinLengthOutput::fromExtension(AuthenticationExtension::create('appid', 6));
    }

    #[Test]
    public function fromExtensionRejectsNonIntegerValue(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must be an integer');

        MinPinLengthOutput::fromExtension(AuthenticationExtension::create('minPinLength', '6'));
    }

    #[Test]
    public function constructorRejectsNegativeValue(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('non-negative');

        new MinPinLengthOutput(-1);
    }
}
