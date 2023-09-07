<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class AuthenticationExtensionsClientTest extends TestCase
{
    #[Test]
    public function anAuthenticationExtensionsClientCanBeCreatedAndValueAccessed(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        static::assertSame('name', $extension->name);
        static::assertSame(['value'], $extension->value);
        static::assertSame('["value"]', json_encode($extension, JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function theAuthenticationExtensionsClientInputsCanManageExtensions(): void
    {
        $inputs = AuthenticationExtensionsClientInputs::create([
            AuthenticationExtension::create('name', ['value']),
        ]);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', json_encode($inputs, JSON_THROW_ON_ERROR));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }

    #[Test]
    public function theAuthenticationExtensionsClientOutputsCanManageExtensions(): void
    {
        $inputs = AuthenticationExtensionsClientOutputs::create([
            AuthenticationExtension::create('name', ['value']),
        ]);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', json_encode($inputs, JSON_THROW_ON_ERROR));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }
}
