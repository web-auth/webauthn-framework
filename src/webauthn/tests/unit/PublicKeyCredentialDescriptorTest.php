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

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
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
    use ProphecyTrait;

    /**
     * @test
     */
    public function anPublicKeyCredentialDescriptorCanBeCreatedAndValueAccessed(): void
    {
        $descriptor = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);

        static::assertEquals('type', $descriptor->getType());
        static::assertEquals('id', $descriptor->getId());
        static::assertEquals(['transport'], $descriptor->getTransports());
        static::assertEquals('{"type":"type","id":"aWQ","transports":["transport"]}', json_encode($descriptor));

        $created = PublicKeyCredentialDescriptor::createFromString('{"type":"type","id":"aWQ=","transports":["transport"]}');
        static::assertEquals($descriptor, $created);
    }
}
