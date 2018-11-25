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

namespace U2F\Tests\Unit;

use PHPUnit\Framework\TestCase;
use U2F\PublicKey;

/**
 * @group unit
 */
final class PublicKeyTest extends TestCase
{
    /**
     * @test
     */
    public function aPublicKeyCanBeCreatedAndSerialized()
    {
        $key = new PublicKey(
            'foo'
        );

        static::assertEquals('foo', $key->getValue());
        static::assertEquals('Zm9v', $key->jsonSerialize());
        static::assertEquals('foo', $key->__toString());
    }
}
