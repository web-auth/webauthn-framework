<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AuthenticationExtensionsClientTest extends AbstractTestCase
{
    #[Test]
    public function anAuthenticationExtensionsClientCanBeCreatedAndValueAccessed(): void
    {
        $extension = new AuthenticationExtension('name', ['value']);

        static::assertSame('name', $extension->name);
        static::assertSame(['value'], $extension->value);
        static::assertSame('["value"]', $this->getSerializer()->serialize($extension, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }

    #[Test]
    public function theAuthenticationExtensionsClientInputsCanManageExtensions(): void
    {
        $inputs = AuthenticationExtensionsClientInputs::create([
            AuthenticationExtension::create('name', ['value']),
        ]);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', $this->getSerializer()->serialize($inputs, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }

    #[Test]
    public function theAuthenticationExtensionsClientOutputsCanManageExtensions(): void
    {
        $inputs = AuthenticationExtensionsClientOutputs::create([
            AuthenticationExtension::create('name', ['value']),
        ]);

        static::assertSame(1, $inputs->count());
        static::assertSame('{"name":["value"]}', $this->getSerializer()->serialize($inputs, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
        static::assertContainsOnlyInstancesOf(AuthenticationExtension::class, $inputs);
    }
}
