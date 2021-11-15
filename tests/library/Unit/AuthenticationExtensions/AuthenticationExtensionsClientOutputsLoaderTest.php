<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\TrueObject;
use CBOR\SignedIntegerObject;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;

/**
 * @internal
 */
final class AuthenticationExtensionsClientOutputsLoaderTest extends TestCase
{
    /**
     * @test
     */
    public function theExtensionsCanBeLoaded(): void
    {
        $cbor = new MapObject([new MapItem(new ByteStringObject('loc'), new TrueObject())]);

        $extensions = AuthenticationExtensionsClientOutputsLoader::load($cbor);

        static::assertInstanceOf(AuthenticationExtensionsClientOutputs::class, $extensions);
        static::assertCount(1, $extensions);
        static::assertSame('{"loc":true}', json_encode($extensions));
    }

    /**
     * @test
     */
    public function theCBORObjectIsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid extension object');
        $cbor = new ByteStringObject('loc');

        AuthenticationExtensionsClientOutputsLoader::load($cbor);
    }

    /**
     * @test
     */
    public function theMapKeyIsNotAString(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid extension key');
        $cbor = new MapObject([new MapItem(SignedIntegerObject::create(-100), new TrueObject())]);

        AuthenticationExtensionsClientOutputsLoader::load($cbor);
    }
}
