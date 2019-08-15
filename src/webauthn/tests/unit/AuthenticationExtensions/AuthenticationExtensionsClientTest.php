<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @group unit
 * @group Fido2
 */
class AuthenticationExtensionsClientTest extends TestCase
{
    /**
     * @test
     *
     * @covers \Webauthn\AuthenticationExtensions\AuthenticationExtension
     */
    public function anAuthenticationExtensionsClientCanBeCreatedAndValueAccessed(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        static::assertEquals('name', $extension->name());
        static::assertEquals(['value'], $extension->value());
        static::assertEquals('["value"]', json_encode($extension));
    }

    /**
     * @test
     *
     * @covers \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs
     */
    public function theAuthenticationExtensionsClientInputsCanManageExtensions(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        $inputs = new AuthenticationExtensionsClientInputs();
        $inputs->add($extension);

        static::assertEquals(1, $inputs->count());
        static::assertEquals('{"name":["value"]}', json_encode($inputs));
        foreach ($inputs as $k => $input) {
            static::assertInstanceOf(AuthenticationExtension::class, $input);
        }
    }

    /**
     * @test
     *
     * @covers \Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs
     */
    public function theAuthenticationExtensionsClientOutputsCanManageExtensions(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        $inputs = new AuthenticationExtensionsClientOutputs();
        $inputs->add($extension);

        static::assertEquals(1, $inputs->count());
        static::assertEquals('{"name":["value"]}', json_encode($inputs));
        foreach ($inputs as $k => $input) {
            static::assertInstanceOf(AuthenticationExtension::class, $input);
        }
    }
}
