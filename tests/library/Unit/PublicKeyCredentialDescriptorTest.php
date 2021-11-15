<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * @internal
 */
final class PublicKeyCredentialDescriptorTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialDescriptorCanBeCreatedAndValueAccessed(): void
    {
        $descriptor = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        static::assertSame('type', $descriptor->getType());
        static::assertSame('id', $descriptor->getId());
        static::assertSame(['transport'], $descriptor->getTransports());
        static::assertSame('{"type":"type","id":"aWQ","transports":["transport"]}', json_encode($descriptor));
    }
}
