<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\MinPinLengthInputExtension;

/**
 * @internal
 */
final class MinPinLengthInputExtensionTest extends TestCase
{
    #[Test]
    public function enableProducesMinPinLengthTrue(): void
    {
        $extension = MinPinLengthInputExtension::enable();

        static::assertSame('minPinLength', $extension->name);
        static::assertTrue($extension->value);
    }

    #[Test]
    public function disableProducesMinPinLengthFalse(): void
    {
        $extension = MinPinLengthInputExtension::disable();

        static::assertSame('minPinLength', $extension->name);
        static::assertFalse($extension->value);
    }
}
