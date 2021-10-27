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
        $descriptor = new PublicKeyCredentialDescriptor('type', 'id', ['transport']);

        static::assertSame('type', $descriptor->getType());
        static::assertSame('id', $descriptor->getId());
        static::assertSame(['transport'], $descriptor->getTransports());
        static::assertSame('{"type":"type","id":"aWQ","transports":["transport"]}', json_encode($descriptor));

        $created = PublicKeyCredentialDescriptor::createFromString(
            '{"type":"type","id":"aWQ=","transports":["transport"]}'
        );
        static::assertSame($descriptor, $created);
    }
}
