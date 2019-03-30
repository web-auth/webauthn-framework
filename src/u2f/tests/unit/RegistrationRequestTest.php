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

use Base64Url\Base64Url;
use PHPUnit\Framework\TestCase;
use U2F\KeyHandler;
use U2F\PublicKey;
use U2F\RegisteredKey;
use U2F\RegistrationRequest;

/**
 * @group unit
 */
final class RegistrationRequestTest extends TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid registered keys list.
     */
    public function theRegistrationRequestDoesNotContainValidRegisteredKeys(): void
    {
        new RegistrationRequest('https://twofactors:4043', ['bad value']);
    }

    /**
     * @test
     */
    public function iCanCreateARegistrationRequestAndUseIt(): void
    {
        $registered_key = new RegisteredKey(
            'U2F_V2',
            new KeyHandler('foo'),
            new PublicKey('bar'),
            'bar'
        );
        $request = new RegistrationRequest(
            'https://twofactors:4043',
            [$registered_key]
        );

        static::assertEquals('https://twofactors:4043', $request->getApplicationId());
        static::assertEquals(32, mb_strlen($request->getChallenge(), '8bit'));
        static::assertArrayHasKey('registerRequests', $request->jsonSerialize());
        static::assertArrayHasKey('registeredKeys', $request->jsonSerialize());
        static::assertArrayHasKey('appId', $request->jsonSerialize());
        static::assertIsArray($request->jsonSerialize()['registerRequests']);
        static::assertEquals(1, \count($request->jsonSerialize()['registerRequests']));
        static::assertIsArray($request->jsonSerialize()['registeredKeys']);
        static::assertEquals(1, \count($request->jsonSerialize()['registeredKeys']));
        static::assertEquals([Base64Url::encode('foo') => $registered_key], $request->getRegisteredKeys());
    }
}
