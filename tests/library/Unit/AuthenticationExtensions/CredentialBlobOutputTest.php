<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\CredentialBlobAssertionOutput;
use Webauthn\AuthenticationExtensions\CredentialBlobRegistrationOutput;
use Webauthn\Exception\AuthenticationExtensionException;

/**
 * @internal
 */
final class CredentialBlobOutputTest extends TestCase
{
    #[Test]
    public function registrationOutputAbsentReturnsNull(): void
    {
        static::assertNull(CredentialBlobRegistrationOutput::fromExtensions(new AuthenticationExtensions([])));
    }

    #[Test]
    public function registrationOutputParsesBoolean(): void
    {
        $output = CredentialBlobRegistrationOutput::fromExtensions(new AuthenticationExtensions([
            AuthenticationExtension::create('credBlob', true),
        ]));

        static::assertNotNull($output);
        static::assertTrue($output->stored);
    }

    #[Test]
    public function registrationOutputRejectsNonBoolean(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must be a boolean');

        CredentialBlobRegistrationOutput::fromExtension(AuthenticationExtension::create('credBlob', 'oops'));
    }

    #[Test]
    public function registrationOutputRejectsWrongName(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('not a "credBlob"');

        CredentialBlobRegistrationOutput::fromExtension(AuthenticationExtension::create('appid', true));
    }

    #[Test]
    public function assertionOutputAbsentReturnsNull(): void
    {
        static::assertNull(CredentialBlobAssertionOutput::fromExtensions(new AuthenticationExtensions([])));
    }

    #[Test]
    public function assertionOutputParsesBlobBytes(): void
    {
        $bytes = "\x10\x20\x30hello";
        $output = CredentialBlobAssertionOutput::fromExtensions(new AuthenticationExtensions([
            AuthenticationExtension::create('credBlob', $bytes),
        ]));

        static::assertNotNull($output);
        static::assertSame($bytes, $output->blob);
    }

    #[Test]
    public function assertionOutputAcceptsEmptyBlob(): void
    {
        $output = CredentialBlobAssertionOutput::fromExtension(AuthenticationExtension::create('credBlob', ''));

        static::assertSame('', $output->blob);
    }

    #[Test]
    public function assertionOutputRejectsNonString(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must be a byte string');

        CredentialBlobAssertionOutput::fromExtension(AuthenticationExtension::create('credBlob', true));
    }

    #[Test]
    public function assertionOutputRejectsBlobOver32Bytes(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('must not exceed 32 bytes');

        new CredentialBlobAssertionOutput(str_repeat('A', 33));
    }
}
