<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @group unit
 * @group Fido2
 *
 * @internal
 */
class AuthenticationExtensionsClientTest extends TestCase
{
    use ProphecyTrait;

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
