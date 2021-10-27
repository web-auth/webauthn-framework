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
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;

/**
 * @internal
 */
final class AuthenticationExtensionsClientTest extends TestCase
{
    /**
     * @test
     */
    public function anAuthenticationExtensionsClientCanBeCreatedAndValueAccessed(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        static::assertSame('name', $extension->name());
        static::assertSame(['value'], $extension->value());
        static::assertSame('["value"]', json_encode($extension));
    }

    /**
     * @test
     */
    public function theAuthenticationExtensionsClientInputsCanManageExtensions(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        $inputs = new AuthenticationExtensionsClientInputs();
        $inputs->add($extension);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', json_encode($inputs));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }

    /**
     * @test
     */
    public function theAuthenticationExtensionsClientOutputsCanManageExtensions(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        $inputs = new AuthenticationExtensionsClientOutputs();
        $inputs->add($extension);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', json_encode($inputs));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }
}
