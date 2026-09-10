<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\CredentialBlobInputExtension;
use Webauthn\AuthenticationExtensions\GetCredentialBlobInputExtension;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @internal
 */
final class CredentialBlobInputExtensionTest extends TestCase
{
    #[Test]
    public function withBlobEncodesPayloadAsBase64Url(): void
    {
        $raw = "\x00\x01\x02secret";
        $extension = CredentialBlobInputExtension::withBlob($raw);

        static::assertSame('credBlob', $extension->name);
        static::assertSame(Base64UrlSafe::encodeUnpadded($raw), $extension->value);
    }

    #[Test]
    public function withBlobAcceptsExactlyMaxLength(): void
    {
        $raw = str_repeat('A', CredentialBlobInputExtension::MAX_LENGTH);
        $extension = CredentialBlobInputExtension::withBlob($raw);

        static::assertSame(Base64UrlSafe::encodeUnpadded($raw), $extension->value);
    }

    #[Test]
    public function withBlobRejectsPayloadAbove32Bytes(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must not exceed 32 bytes');

        CredentialBlobInputExtension::withBlob(str_repeat('A', 33));
    }

    #[Test]
    public function getCredBlobEnableProducesTrue(): void
    {
        $extension = GetCredentialBlobInputExtension::enable();

        static::assertSame('getCredBlob', $extension->name);
        static::assertTrue($extension->value);
    }

    #[Test]
    public function getCredBlobDisableProducesFalse(): void
    {
        $extension = GetCredentialBlobInputExtension::disable();

        static::assertSame('getCredBlob', $extension->name);
        static::assertFalse($extension->value);
    }
}
