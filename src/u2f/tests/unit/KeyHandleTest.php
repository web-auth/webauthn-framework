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

namespace U2F\Tests\Unit;

use PHPUnit\Framework\TestCase;
use U2F\KeyHandler;

/**
 * @group unit
 */
final class KeyHandleTest extends TestCase
{
    /**
     * @test
     */
    public function aKeyHandleCanBeCreatedAndSerialized(): void
    {
        $handle = new KeyHandler(
            'foo'
        );

        static::assertEquals('foo', $handle->getValue());
        static::assertEquals('Zm9v', $handle->jsonSerialize());
        static::assertEquals('foo', $handle->__toString());
    }
}
