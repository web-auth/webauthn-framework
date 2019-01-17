<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\TrueObject;
use CBOR\SignedIntegerObject;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader
 */
class AuthenticationExtensionsClientOutputsLoaderTest extends TestCase
{
    /**
     * @test
     */
    public function theExtensionsCanBeLoaded(): void
    {
        $cbor = new MapObject([
            new MapItem(new ByteStringObject('loc'), new TrueObject()),
        ]);

        $extensions = AuthenticationExtensionsClientOutputsLoader::load($cbor);

        static::assertInstanceOf(AuthenticationExtensionsClientOutputs::class, $extensions);
        static::assertCount(1, $extensions);
        static::assertEquals('{"loc":true}', \Safe\json_encode($extensions));
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid extension object
     */
    public function theCBORObjectIsInvalid(): void
    {
        $cbor = new ByteStringObject('loc');

        AuthenticationExtensionsClientOutputsLoader::load($cbor);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid extension key
     */
    public function theMapKeyIsNotAString(): void
    {
        $cbor = new MapObject([
            new MapItem(SignedIntegerObject::createFromGmpValue(gmp_init(-100)), new TrueObject()),
        ]);

        AuthenticationExtensionsClientOutputsLoader::load($cbor);
    }
}
