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

namespace Webauthn\Tests\Unit;

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use Webauthn\CollectedClientData;
use Webauthn\TokenBinding\TokenBinding;

/**
 * @group unit
 * @group Fido2
 *
 * @covers \Webauthn\CollectedClientData
 */
class CollectedClientDataTest extends TestCase
{
    /**
     * @test
     */
    public function anCollectedClientDataCanBeCreatedAndValueAccessed(): void
    {
        $collectedClientData = new CollectedClientData(
            'raw_data',
            [
                'type' => 'type',
                'origin' => 'origin',
                'challenge' => Base64Url::encode('challenge'),
                'extensions' => 'extensions',
                'tokenBinding' => ['status' => 'present', 'id' => Base64Url::encode('id')],
            ]
        );

        static::assertEquals('raw_data', $collectedClientData->getRawData());
        static::assertEquals('origin', $collectedClientData->getOrigin());
        static::assertEquals('challenge', $collectedClientData->getChallenge());
        static::assertInstanceOf(TokenBinding::class, $collectedClientData->getTokenBinding());
        static::assertEquals('id', $collectedClientData->getTokenBinding()->getId());
        static::assertEquals('present', $collectedClientData->getTokenBinding()->getStatus());
        static::assertEquals('type', $collectedClientData->getType());
        static::assertEquals(['type', 'origin', 'challenge', 'extensions', 'tokenBinding'], $collectedClientData->all());
        static::assertTrue($collectedClientData->has('extensions'));
        static::assertEquals('extensions', $collectedClientData->get('extensions'));
    }
}
