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

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use U2F\ClientData;

/**
 * @group unit
 */
final class ClientDataTest extends TestCase
{
    /**
     * @test
     * @expectedException \Safe\Exceptions\JsonException
     * @expectedExceptionMessage Syntax error
     */
    public function theClientDataIsNotBase64UrlEncoded()
    {
        new ClientData(
            'foo'
        );
    }

    /**
     * @test
     * @expectedException \Safe\Exceptions\JsonException
     * @expectedExceptionMessage Syntax error
     */
    public function theClientDataIsNotAnArray()
    {
        new ClientData(
            Base64Url::encode('foo')
        );
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid client data.
     */
    public function theClientDataDoesNotContainTheMandatoryKeys()
    {
        new ClientData(
            Base64Url::encode(json_encode([]))
        );
    }

    /**
     * @test
     */
    public function theClientDataIsValid()
    {
        $data = json_encode([
            'typ' => 'foo',
            'challenge' => Base64Url::encode('bar'),
            'origin' => 'here',
            'cid_pubkey' => 'none',
        ]);
        $client_data = new ClientData(
            Base64Url::encode($data)
        );

        static::assertEquals('foo', $client_data->getType());
        static::assertEquals('bar', $client_data->getChallenge());
        static::assertEquals('here', $client_data->getOrigin());
        static::assertEquals('none', $client_data->getChannelIdPublicKey());
        static::assertEquals($data, $client_data->getRawData());
    }
}
