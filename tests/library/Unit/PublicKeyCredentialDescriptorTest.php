<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\PublicKeyCredentialDescriptor
 *
 * @internal
 */
class PublicKeyCredentialDescriptorTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialDescriptorCanBeCreatedAndValueAccessed(): void
    {
        $descriptor = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        static::assertEquals('type', $descriptor->getType());
        static::assertEquals('id', $descriptor->getId());
        static::assertEquals(['transport'], $descriptor->getTransports());
        static::assertEquals('{"type":"type","id":"aWQ","transports":["transport"]}', json_encode($descriptor));

        $created = PublicKeyCredentialDescriptor::createFromString('{"type":"type","id":"aWQ=","transports":["transport"]}');
        static::assertEquals($descriptor, $created);
    }
}
