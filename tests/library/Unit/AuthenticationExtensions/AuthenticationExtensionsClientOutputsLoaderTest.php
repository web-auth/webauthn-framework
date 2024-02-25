<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\TrueObject;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Exception\AuthenticationExtensionException;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class AuthenticationExtensionsLoaderTest extends TestCase
{
    #[Test]
    public function theExtensionsCanBeLoaded(): void
    {
        $cbor = new MapObject([new MapItem(new ByteStringObject('loc'), new TrueObject())]);

        $extensions = AuthenticationExtensionsLoader::load($cbor);

        static::assertInstanceOf(AuthenticationExtensions::class, $extensions);
        static::assertCount(1, $extensions);
        static::assertSame('{"loc":true}', json_encode($extensions, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function theCBORObjectIsInvalid(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('Invalid extension object');
        $cbor = new ByteStringObject('loc');

        AuthenticationExtensionsLoader::load($cbor);
    }
}
